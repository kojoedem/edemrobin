# routes_vlan.py
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from sqlalchemy.orm import Session
from database import get_db
from security import get_current_user, level_required
import crud

router = APIRouter(prefix="/vlan", tags=["VLAN"])

@router.post("/add")
@level_required(2)
def add_vlan(
    request: Request,
    vlan_id: int = Form(...),
    name: str = Form(...),
    site: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """
    Handles the creation of a new VLAN.

    - Requires user to have at least level 2 privileges.
    - Checks for uniqueness of the VLAN ID before creation.
    """
    user = get_current_user(request, db)
    if crud.get_vlan_by_id(db, vlan_id):
        raise HTTPException(status_code=400, detail="VLAN ID already exists")
    v = crud.create_vlan(db, vlan_id=vlan_id, name=name, site=site, created_by=user.username)
    return {"msg": "VLAN created", "vlan": v.vlan_id}
