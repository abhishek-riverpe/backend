from fastapi import APIRouter, Depends, HTTPException, status
from prisma.models import User

from .. import auth, schemas
from ..database import db

router = APIRouter(
    prefix="/api/v1/account",
    tags=["account"],
)

@router.get("/balance")
async def get_balance(current_user: User = Depends(auth.get_current_user)):
    account = await db.account.find_unique(where={"userId": current_user.id})
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    
    return {"balance": f"{account.balance:.2f}"}


@router.post("/transfer")
async def transfer(transfer_data: schemas.TransferRequest, current_user: User = Depends(auth.get_current_user)):
    async with db.tx() as transaction:
        sender_account = await transaction.account.find_unique(where={"userId": current_user.id})

        if not sender_account or sender_account.balance < transfer_data.amount:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient balance")

        recipient_account = await transaction.account.find_unique(where={"userId": transfer_data.to})
        if not recipient_account:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid recipient account")

        await transaction.account.update(
            where={"userId": current_user.id},
            data={"balance": {"decrement": transfer_data.amount}}
        )
        await transaction.account.update(
            where={"userId": transfer_data.to},
            data={"balance": {"increment": transfer_data.amount}}
        )

    return {"message": "Transfer successful"}
