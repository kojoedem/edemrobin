import io
import ipaddress
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Request
from sqlalchemy.orm import Session
from ciscoconfparse import CiscoConfParse

from database import get_db
from models import SubnetStatus
import crud
from security import get_current_user, admin_required

router = APIRouter(prefix="/import", tags=["Import"])


@router.post("/cisco-config", dependencies=[Depends(admin_required)])
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
    imported = 0
    for intf in intfs:
        name = intf.text.split(None, 1)[1].strip()
        iface = crud.get_or_create_interface(db, device, name)

        ip_lines = intf.re_search_children(r"^\s+ip address\s+")
        for l in ip_lines:
            # Example: " ip address 192.168.10.1 255.255.255.0"
            parts = l.text.strip().split()
            if len(parts) >= 4:
                ip = parts[2]
                mask = parts[3]
                try:
                    network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                except ValueError:
                    continue

                # Decide/ensure block
                block_cidr = crud.suggest_block_for_network(network)
                block = crud.get_or_create_block(db, block_cidr, created_by=user.username, description="auto-import")

                # Ensure subnet exists
                subnet = crud.create_or_get_subnet(
                    db,
                    str(network.with_prefixlen),
                    block,
                    status=SubnetStatus.imported,
                    created_by=user.username
                )

                # Add the interface address record
                crud.add_interface_address(db, iface, ip=str(ip), prefix=network.prefixlen, subnet_id=subnet.id)
                imported += 1

    return {"msg": f"Imported {imported} interface IP(s) from {file.filename}", "device": device.hostname}
