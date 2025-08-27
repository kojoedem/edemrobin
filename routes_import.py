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

    # --- First Pass: Collect all required parent objects ---

    required_parent_cidrs = set()
    required_vlan_nums = set()

    # Parse parent blocks from form input
    parent_networks = []
    if parent_blocks:
        cidrs = [cidr.strip() for cidr in parent_blocks.split(",")]
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr)
                parent_networks.append(net)
                required_parent_cidrs.add(str(net))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid CIDR format: {cidr}")

    intfs = parse.find_objects(r"^interface\s+")
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()
        if '.' in name:
            try:
                vlan_num = int(name.split('.')[-1])
                required_vlan_nums.add(vlan_num)
            except ValueError:
                pass

    # --- Creation Phase: Ensure all parent objects exist ---

    hostname = parse.find_lines(r"^hostname\s+")
    hostname = hostname[0].split()[1] if hostname else f"device-{file.filename}"
    device = crud.get_or_create_device(db, hostname=hostname)

    crud.get_or_create_block(db, "Unassigned", description="For imported subnets that do not fit into any specified parent block.")

    for cidr in required_parent_cidrs:
        crud.get_or_create_block(db, cidr, created_by=user.username)

    for vlan_num in required_vlan_nums:
        crud.get_or_create_vlan(db, vlan_id=vlan_num, created_by=user.username)

    # --- Second Pass: Import the data, now that parents are guaranteed to exist ---

    imported = 0
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()
        iface = crud.get_or_create_interface(db, device, name)

        is_shutdown = len(intf.re_search_children(r"^\s*shutdown\s*$")) > 0

        vlan_id_to_associate = None
        if '.' in name:
            try:
                vlan_num = int(name.split('.')[-1])
                vlan = crud.get_vlan_by_id(db, vlan_num)
                if vlan:
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

                    assigned_parent = next((p_net for p_net in parent_networks if network.subnet_of(p_net)), None)

                    status = SubnetStatus.imported
                    if is_shutdown:
                        status = SubnetStatus.deactivated
                    elif assigned_parent is None:
                        status = SubnetStatus.inactive

                    parent_cidr = str(assigned_parent) if assigned_parent else "Unassigned"
                    parent_block_obj = db.query(crud.IPBlock).filter(crud.IPBlock.cidr == parent_cidr).first()

                    subnet = crud.create_or_get_subnet(
                        db, str(network.with_prefixlen), parent_block_obj,
                        status=status, created_by=user.username,
                        vlan_id=vlan_id_to_associate, description=description
                    )

                    crud.add_interface_address(db, iface, ip=ip, prefix=network.prefixlen, subnet_id=subnet.id)
                    imported += 1

                except ValueError:
                    continue

    return RedirectResponse(url="/", status_code=303)
