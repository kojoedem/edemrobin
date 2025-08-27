import io
import ipaddress
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Request, Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from ciscoconfparse import CiscoConfParse

from database import get_db
from models import SubnetStatus, User, IPBlock, NatIp
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
    parse = CiscoConfParse(io.StringIO(content).read().splitlines(), factory=True)

    # --- First Pass: Collect all required parent objects ---
    required_parent_cidrs = set()
    required_client_names = set()
    interface_to_description = {}

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
    vlan_info = {}
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()
        description = ""
        desc_line = intf.re_search_children(r"^\s+description\s+")
        if desc_line:
            description = desc_line[0].text.strip().split(None, 1)[1]
        interface_to_description[name] = description

        # Collect all descriptions as potential clients
        if description:
            required_client_names.add(description)

        # Collect VLAN info
        if '.' in name:
            try:
                vlan_num = int(name.split('.')[-1])
                if vlan_num not in vlan_info or description:
                    vlan_info[vlan_num] = description
            except ValueError:
                pass

    # --- Creation Phase: Ensure all parent objects exist ---
    hostname = parse.find_lines(r"^hostname\s+")
    hostname = hostname[0].split()[1] if hostname else f"device-{file.filename}"
    device = crud.get_or_create_device(db, hostname=hostname)

    crud.get_or_create_block(db, "Unassigned", description="For imported subnets that do not fit into any specified parent block.")

    for cidr in required_parent_cidrs:
        crud.get_or_create_block(db, cidr, created_by=user.username)

    for vlan_num, description in vlan_info.items():
        vlan_name = description if description else f"VLAN-{vlan_num}"
        crud.get_or_create_vlan(db, vlan_id=vlan_num, created_by=user.username, name=vlan_name)

    # Create clients from descriptions, but set them as inactive by default
    for name in required_client_names:
        crud.get_or_create_client(db, name=name, is_active=False)

    # --- Second Pass: Import NAT IPs ---
    # [BUG FIX] Define route_lines before this pass
    route_lines = parse.find_lines(r"^ip\s+route\s+")
    for line in route_lines:
        parts = line.split()
        ip_to_check = ""
        iface_name = ""
        if len(parts) >= 3 and parts[2] == "vrf":
            if len(parts) >= 7:
                ip_to_check = parts[4]
                iface_name = parts[6]
        elif len(parts) >= 5:
            ip_to_check = parts[2]
            iface_name = parts[4]

        if ip_to_check and iface_name:
            client_name = interface_to_description.get(iface_name)
            if client_name:
                client = crud.get_client_by_name(db, client_name)
                if client:
                    try:
                        nat_ip_cidr = f"{ip_to_check}/32"
                        existing_nat = db.query(NatIp).filter_by(ip_address=nat_ip_cidr).first()
                        if not existing_nat:
                            crud.create_nat_ip(db, ip_address=nat_ip_cidr, client_id=client.id, description="Imported from route")
                    except Exception:
                        db.rollback()

    # --- Third Pass: Import interface subnets ---
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()
        iface = crud.get_or_create_interface(db, device, name)

        is_shutdown = len(intf.re_search_children(r"^\s*shutdown\s*$")) > 0

        description = interface_to_description.get(name, "")
        client = crud.get_client_by_name(db, description) if description else None

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
                    parent_block_obj = db.query(IPBlock).filter(IPBlock.cidr == parent_cidr).first()

                    if parent_block_obj is None:
                        continue

                    subnet = crud.create_or_get_subnet(
                        db, str(network.with_prefixlen), parent_block_obj,
                        status=status, created_by=user.username,
                        client_id=client.id if client else None,
                        description=description
                    )
                    crud.add_interface_address(db, iface, ip=ip, prefix=network.prefixlen, subnet_id=subnet.id)

                except ValueError:
                    continue

    return RedirectResponse(url="/", status_code=303)
