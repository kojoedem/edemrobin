import io
import ipaddress
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Request, Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from ciscoconfparse import CiscoConfParse

from database import get_db
from models import SubnetStatus, User
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

    # Guess hostname if present
    hostname = None
    h = parse.find_lines(r"^hostname\s+")
    if h:
        hostname = h[0].split()[1]
    if not hostname:
        hostname = f"device-{file.filename}"

    device = crud.get_or_create_device(db, hostname=hostname)

    # Get or create the 'Unassigned' block for IPs that don't fit into specified parents
    unassigned_block = crud.get_or_create_block(db, "Unassigned", description="For imported subnets that do not fit into any specified parent block.")

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
        iface = crud.get_or_create_interface(db, device, name)

        is_shutdown = len(intf.re_search_children(r"^\s*shutdown\s*$")) > 0

        # Try to parse VLAN ID from sub-interface name
        vlan_id_to_associate = None
        if '.' in name:
            try:
                vlan_num = int(name.split('.')[-1])
                vlan = crud.get_vlan_by_id(db, vlan_num)
                if not vlan:
                    vlan = crud.create_vlan(db, vlan_id=vlan_num, name=f"VLAN-{vlan_num}", created_by=user.username)
                vlan_id_to_associate = vlan.id
            except ValueError:
                pass  # Not a valid VLAN sub-interface

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

            # Find parent block
            assigned_parent = None
            for p_net in parent_networks:
                if network.subnet_of(p_net):
                    assigned_parent = p_net
                    break

            # Determine status
            if net_info["is_shutdown"]:
                status = SubnetStatus.deactivated
            elif assigned_parent is None:
                status = SubnetStatus.inactive
            else:
                status = SubnetStatus.imported

            # Determine parent block for DB
            if assigned_parent:
                parent_block_obj = crud.get_or_create_block(db, str(assigned_parent), created_by=user.username)
            else:
                parent_block_obj = unassigned_block

            # Create subnet
            subnet = crud.create_or_get_subnet(
                db,
                str(network.with_prefixlen),
                parent_block_obj,
                status=status,
                created_by=user.username,
                vlan_id=net_info["vlan_id"],
                description=net_info["description"]
            )

            # Add the interface address record
            crud.add_interface_address(db, net_info["iface"], ip=net_info["ip"], prefix=network.prefixlen, subnet_id=subnet.id)
            imported += 1

    return RedirectResponse(url="/", status_code=303)
