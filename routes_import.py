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

from utils import parse_mikrotik_config

@router.post("/config", dependencies=[Depends(require_admin)])
def import_config(
    request: Request,
    file: UploadFile = File(...),
    config_type: str = Form(...),
    parent_blocks: str = Form(""),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded.")

    content = file.file.read().decode(errors="ignore")

    # --- Parent Block Processing ---
    parent_networks = []
    if parent_blocks:
        # Use user-provided blocks
        cidrs = [cidr.strip() for cidr in parent_blocks.split(",")]
        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr)
                parent_networks.append(net)
                # Ensure these blocks exist
                crud.get_or_create_block(db, cidr, created_by=user.username)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid CIDR format: {cidr}")
    else:
        # No blocks provided, so use all existing blocks from DB
        existing_blocks = db.query(IPBlock).filter(IPBlock.cidr != "Unassigned").all()
        for block in existing_blocks:
            try:
                parent_networks.append(ipaddress.ip_network(block.cidr))
            except ValueError:
                continue # Ignore invalid CIDRs in the database

    # --- Pre-computation and Object Creation ---
    crud.get_or_create_block(db, "Unassigned", description="For imported subnets that do not fit into any specified parent block.")

    if config_type == "cisco":
        handle_cisco_import(db, user, content, parent_networks, file.filename)
    elif config_type == "mikrotik":
        handle_mikrotik_import(db, user, content, parent_networks, file.filename)
    else:
        raise HTTPException(status_code=400, detail="Invalid config type selected.")

    return RedirectResponse(url="/", status_code=303)


def handle_cisco_import(db: Session, user: User, content: str, parent_networks: list, filename: str):
    parse = CiscoConfParse(io.StringIO(content).splitlines(), factory=True)

    required_client_names = set()
    interface_to_description = {}
    vlan_info = {}

    intfs = parse.find_objects(r"^interface\s+")
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()
        description_line = intf.re_search_children(r"^\s+description\s+")
        description = description_line[0].text.strip().split(None, 1)[1] if description_line else ""
        interface_to_description[name] = description
        if description:
            required_client_names.add(description)
        if '.' in name:
            try:
                vlan_num = int(name.split('.')[-1])
                if vlan_num not in vlan_info or description:
                    vlan_info[vlan_num] = description
            except ValueError:
                pass

    hostname = parse.find_lines(r"^hostname\s+")
    hostname = hostname[0].split()[1] if hostname else f"cisco-device-{filename}"
    device = crud.get_or_create_device(db, hostname=hostname)

    for vlan_num, desc in vlan_info.items():
        vlan_name = desc if desc else f"VLAN-{vlan_num}"
        crud.get_or_create_vlan(db, vlan_id=vlan_num, created_by=user.username, name=vlan_name)

    for name in required_client_names:
        crud.get_or_create_client(db, name=name, is_active=False)

    # Second Pass: Import NAT IPs from routes
    route_lines = parse.find_lines(r"^ip\s+route\s+")
    for line in route_lines:
        parts = line.split()
        ip_to_check = ""
        iface_name = ""
        # Handle VRF routes: ip route vrf NAME ...
        if len(parts) >= 3 and parts[2] == "vrf":
            if len(parts) >= 7:
                ip_to_check = parts[4]
                iface_name = parts[6]
        # Handle global routes
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
                        if not db.query(NatIp).filter_by(ip_address=nat_ip_cidr).first():
                            crud.create_nat_ip(db, ip_address=nat_ip_cidr, client_id=client.id, description="Imported from Cisco route")
                    except Exception:
                        db.rollback()

    # Third Pass: Import interface subnets
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()
        iface = crud.get_or_create_interface(db, device, name)
        is_shutdown = len(intf.re_search_children(r"^\s*shutdown\s*$")) > 0
        description = interface_to_description.get(name, "")
        client = crud.get_client_by_name(db, description) if description else None

        for l in intf.re_search_children(r"^\s+ip address\s+"):
            parts = l.text.strip().split()
            if len(parts) < 4: continue
            try:
                network = ipaddress.ip_network(f"{parts[2]}/{parts[3]}", strict=False)
                assigned_parent = next((p_net for p_net in parent_networks if network.subnet_of(p_net)), None)
                status = SubnetStatus.deactivated if is_shutdown else (SubnetStatus.imported if assigned_parent else SubnetStatus.inactive)
                parent_cidr = str(assigned_parent) if assigned_parent else "Unassigned"
                parent_block_obj = db.query(IPBlock).filter(IPBlock.cidr == parent_cidr).first()
                if parent_block_obj:
                    subnet = crud.create_or_get_subnet(db, str(network.with_prefixlen), parent_block_obj, status=status, created_by=user.username, client_id=client.id if client else None, description=description)
                    crud.add_interface_address(db, iface, ip=parts[2], prefix=network.prefixlen, subnet_id=subnet.id)
            except ValueError:
                continue

def handle_mikrotik_import(db: Session, user: User, content: str, parent_networks: list, filename: str):
    parsed_data = parse_mikrotik_config(content)

    required_client_names = {addr['comment'] for addr in parsed_data['addresses'] if addr.get('comment')}

    hostname = next((item['name'] for item in parsed_data.get('system', []) if 'name' in item), f"mikrotik-device-{filename}")
    device = crud.get_or_create_device(db, hostname=hostname)

    for name in required_client_names:
        crud.get_or_create_client(db, name=name, is_active=False)

    for addr in parsed_data['addresses']:
        try:
            network = ipaddress.ip_network(addr['address'], strict=False)
            iface_name = addr['interface']
            iface = crud.get_or_create_interface(db, device, iface_name)

            is_disabled = addr.get('disabled') == 'true'
            comment = addr.get('comment', '')
            client = crud.get_client_by_name(db, comment) if comment else None

            assigned_parent = next((p_net for p_net in parent_networks if network.subnet_of(p_net)), None)
            status = SubnetStatus.deactivated if is_disabled else (SubnetStatus.imported if assigned_parent else SubnetStatus.inactive)
            parent_cidr = str(assigned_parent) if assigned_parent else "Unassigned"
            parent_block_obj = db.query(IPBlock).filter(IPBlock.cidr == parent_cidr).first()

            if parent_block_obj:
                subnet = crud.create_or_get_subnet(db, str(network.with_prefixlen), parent_block_obj, status=status, created_by=user.username, client_id=client.id if client else None, description=comment)
                crud.add_interface_address(db, iface, ip=str(network.ip), prefix=network.prefixlen, subnet_id=subnet.id)
        except ValueError:
            continue

    for nat_rule in parsed_data.get('nat_rules', []):
        if nat_rule.get('action') == 'src-nat' and 'to-addresses' in nat_rule:
            client_cidr = nat_rule.get('src-address')
            if not client_cidr: continue

            # Find client based on the source address of the NAT rule
            client = None
            for addr in parsed_data['addresses']:
                if addr['address'] == client_cidr:
                    if addr.get('comment'):
                        client = crud.get_client_by_name(db, addr['comment'])
                    break

            if client:
                try:
                    nat_ip_cidr = f"{nat_rule['to-addresses']}/32"
                    if not db.query(NatIp).filter_by(ip_address=nat_ip_cidr).first():
                        crud.create_nat_ip(db, ip_address=nat_ip_cidr, client_id=client.id, description="Imported from MikroTik NAT")
                except Exception:
                    db.rollback()
