from fastapi import APIRouter, Depends, HTTPException, status
from prisma.models import User

from .. import auth, schemas
from ..database import db

router = APIRouter(
    prefix="/api/v1/user",
    tags=["user"],
)

@router.get("/me")
async def get_me(current_user: User = Depends(auth.get_current_user)):
    return {
        "username": current_user.username,
        "firstName": current_user.first_name,
        "lastName": current_user.last_name,
    }

@router.put("/")
async def update_user(user_update: schemas.UserUpdate, current_user: User = Depends(auth.get_current_user)):
    update_data = user_update.dict(exclude_unset=True)
    
    if "password" in update_data and update_data["password"]:
        update_data["password_hash"] = auth.get_password_hash(update_data.pop("password"))

    if "firstName" in update_data:
        update_data["first_name"] = update_data.pop("firstName")
    
    if "lastName" in update_data:
        update_data["last_name"] = update_data.pop("lastName")

    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No update data provided")

    await db.user.update(
        where={"id": current_user.id},
        data=update_data
    )
    return {"message": "Updated successfully"}


@router.get("/bulk")
async def get_users(filter: str = "", current_user: User = Depends(auth.get_current_user)):
    users = await db.user.find_many(
        where={
            "OR": [
                {"first_name": {"contains": filter, "mode": "insensitive"}},
                {"last_name": {"contains": filter, "mode": "insensitive"}},
            ],
            "NOT": {
                "id": current_user.id
            }
        }
    )
    return {
        "user": [
            {"username": u.username, "firstName": u.first_name, "lastName": u.last_name, "_id": u.id}
            for u in users
        ]
    }
