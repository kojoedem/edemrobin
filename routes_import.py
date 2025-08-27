import io
import ipaddress
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Request
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

    intfs = parse.find_objects(r"^interface\s+")
    networks = []
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()
        iface = crud.get_or_create_interface(db, device, name)

        description = ""
        desc_line = intf.re_search_children(r"^\s+description\s+")
        if desc_line:
            description = desc_line[0].text.strip().split(None, 1)[1]

        ip_lines = intf.re_search_children(r"^\s+ip address\s+")
        for l in ip_lines:
            # Example: " ip address 192.168.10.1 255.255.255.0"
            parts = l.text.strip().split()
            if len(parts) >= 4:
                ip = parts[2]
                mask = parts[3]
                try:
                    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    networks.append(
                        {"network": network, "iface": iface, "ip": ip, "description": description}
                    )
                except ValueError:
                    continue

    imported = 0
    if networks:
        # Calculate single supernet
        nets_to_summarize = [n["network"] for n in networks]
        first_ip = min(net.network_address for net in nets_to_summarize)
        last_ip = max(net.broadcast_address for net in nets_to_summarize)

        supernet = ipaddress.ip_network(f"{first_ip}/32")
        while last_ip not in supernet:
            supernet = supernet.supernet()

        if supernet:
            block = crud.get_or_create_block(
                db, str(supernet), created_by=user.username, description="auto-import-cisco"
            )
        else:
            # Fallback or error
            # For now, just process without a single block, though this case is unlikely with valid IPs
            block = None

        # Create subnets
        for net_info in networks:
            network = net_info["network"]
            iface = net_info["iface"]
            ip = net_info["ip"]
            description = net_info["description"]

            parent_block = block # Use the single block for all subnets

            if parent_block:
                # Ensure subnet exists
                subnet = crud.create_or_get_subnet(
                    db,
                    str(network.with_prefixlen),
                    parent_block,
                    status=SubnetStatus.imported,
                    created_by=user.username,
                    description=description
                )

                # Add the interface address record
                crud.add_interface_address(db, iface, ip=str(ip), prefix=network.prefixlen, subnet_id=subnet.id)
                imported += 1

    return {"msg": f"Imported {imported} interface IP(s) from {file.filename}", "device": device.hostname}
