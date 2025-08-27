import io
import ipaddress
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Request, Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from ciscoconfparse import CiscoConfParse

from database import get_db
from models import SubnetStatus, User, Device, Interface, VLAN, IPBlock
import crud
from security import get_current_user

router = APIRouter(prefix="/import", tags=["Import"])


def require_admin(user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")


@router.post("/cisco-config", dependencies=[Depends(require_admin)])
def import_cisco_config(
    request: Request,
    file: UploadFile = File(...),
    parent_blocks: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)

    if not file.filename.lower().endswith((".txt", ".cfg", ".conf")):
        raise HTTPException(status_code=400, detail="Please upload a Cisco config text file")

    content = file.file.read().decode(errors="ignore")
    parse = CiscoConfParse(io.StringIO(content).read().splitlines())

    # --- Caching dictionaries to prevent duplicate object creation within a single transaction ---
    device_cache: dict[str, Device] = {}
    interface_cache: dict[str, Interface] = {}
    vlan_cache: dict[int, VLAN] = {}
    block_cache: dict[str, IPBlock] = {}

    # Guess hostname
    hostname = parse.find_lines(r"^hostname\s+")
    hostname = hostname[0].split()[1] if hostname else f"device-{file.filename}"

    device = crud.get_or_create_device_no_commit(db, hostname=hostname)
    device_cache[hostname] = device

    # Get or create the 'Unassigned' block
    unassigned_block = crud.get_or_create_block_no_commit(db, "Unassigned", description="For imported subnets that do not fit into any specified parent block.")
    block_cache["Unassigned"] = unassigned_block

    # Parse parent blocks from form input
    parent_networks = []
    if parent_blocks:
        cidrs = [cidr.strip() for cidr in parent_blocks.split(",")]
        for cidr in cidrs:
            try:
                parent_networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid CIDR format: {cidr}")

    intfs = parse.find_objects(r"^interface\s+")
    networks_to_process = []
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()

        if name in interface_cache:
            iface = interface_cache[name]
        else:
            iface = crud.get_or_create_interface_no_commit(db, device, name)
            interface_cache[name] = iface

        is_shutdown = len(intf.re_search_children(r"^\s*shutdown\s*$")) > 0

        # Try to parse VLAN ID from sub-interface name
        vlan_id_to_associate = None
        if '.' in name:
            try:
                vlan_num = int(name.split('.')[-1])
                if vlan_num in vlan_cache:
                    vlan = vlan_cache[vlan_num]
                else:
                    vlan = crud.get_vlan_by_id(db, vlan_num)
                    if not vlan:
                        vlan = crud.create_vlan_no_commit(db, vlan_id=vlan_num, name=f"VLAN-{vlan_num}", created_by=user.username)
                    vlan_cache[vlan_num] = vlan
                vlan_id_to_associate = vlan.id
            except ValueError:
                pass

        description = ""
        desc_line = intf.re_search_children(r"^\s+description\s+")
        if desc_line:
            description = desc_line[0].text.strip().split(None, 1)[1]

        ip_lines = intf.re_search_children(r"^\s+ip address\s+")
        for l in ip_lines:
            parts = l.text.strip().split()
            if len(parts) >= 4:
                ip = parts[2]
                mask = parts[3]
                try:
                    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    networks_to_process.append({
                        "network": network, "iface": iface, "ip": ip,
                        "description": description, "is_shutdown": is_shutdown,
                        "vlan_id": vlan_id_to_associate
                    })
                except ValueError:
                    continue

    imported = 0
    if networks_to_process:
        for net_info in networks_to_process:
            network = net_info["network"]

            assigned_parent = next((p_net for p_net in parent_networks if network.subnet_of(p_net)), None)

            status = SubnetStatus.imported
            if net_info["is_shutdown"]:
                status = SubnetStatus.deactivated
            elif assigned_parent is None:
                status = SubnetStatus.inactive

            parent_block_obj = None
            if assigned_parent:
                parent_cidr = str(assigned_parent)
                if parent_cidr in block_cache:
                    parent_block_obj = block_cache[parent_cidr]
                else:
                    parent_block_obj = crud.get_or_create_block_no_commit(db, parent_cidr, created_by=user.username)
                    block_cache[parent_cidr] = parent_block_obj
            else:
                parent_block_obj = unassigned_block

            subnet = crud.create_or_get_subnet_no_commit(
                db, str(network.with_prefixlen), parent_block_obj,
                status=status, created_by=user.username,
                vlan_id=net_info["vlan_id"], description=net_info["description"]
            )

            crud.add_interface_address_no_commit(db, net_info["iface"], ip=net_info["ip"], prefix=network.prefixlen, subnet_id=subnet.id)
            imported += 1

    db.commit()
    return RedirectResponse(url="/", status_code=303)
