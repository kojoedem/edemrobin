from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import IPBlock, User

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.post("/blocks")
def create_block(cidr: str, description: str = None, db: Session = Depends(get_db)):
    block = IPBlock(cidr=cidr, description=description)
    db.add(block)
    db.commit()
    db.refresh(block)
    return {"msg": "Block created", "block": block.cidr}

@router.post("/assign_block")
def assign_block(user_id: int, block_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    block = db.query(IPBlock).filter(IPBlock.id == block_id).first()
    if not user or not block:
        raise HTTPException(status_code=404, detail="User or Block not found")
    if block not in user.blocks:
        user.blocks.append(block)
        db.commit()
    return {"msg": f"Block {block.cidr} assigned to {user.username}"}
