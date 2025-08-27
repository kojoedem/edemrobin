# routes_allocate.py (or inline in app.py)
import ipaddress
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from sqlalchemy.orm import Session
from database import get_db
from security import get_current_user, level_required
from models import SubnetStatus, IPBlock, Subnet
import crud

router = APIRouter(prefix="/allocate", tags=["Allocate"])


@router.post("/subnet")
@level_required(2)
def allocate_subnet(
    request: Request,
    block_id: int = Form(...),
    prefix: int = Form(...),          # e.g. 29 for /29
    vlan_id: int | None = Form(None),
    description: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    block: IPBlock | None = db.query(IPBlock).filter(IPBlock.id == block_id).first()
    if not block:
        raise HTTPException(status_code=404, detail="Block not found")

    net = ipaddress.ip_network(block.cidr)
    # collect existing subnets under this block
    existing = [ipaddress.ip_network(s.cidr) for s in db.query(Subnet).filter(Subnet.block_id == block_id).all()]

    for cand in net.subnets(new_prefix=prefix):
        if all(not cand.overlaps(x) for x in existing):
            # Free subnet found
            sub = crud.create_or_get_subnet(
                db,
                str(cand),
                block=block,
                status=SubnetStatus.allocated,
                created_by=user.username,
                vlan_id=vlan_id,
                description=description
            )
            return {"msg": "Allocated", "subnet": sub.cidr, "block": block.cidr}

    raise HTTPException(status_code=400, detail="No available subnet of that size in selected block")
