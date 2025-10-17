import random
from fastapi import APIRouter, Depends, HTTPException, status
from prisma.models import User

from .. import auth, schemas
from ..database import db

router = APIRouter(
    prefix="/api/v1/user",
    tags=["user"],
)

@router.post("/signup", response_model=schemas.Token)
async def signup(user_in: schemas.UserCreate):
    existing_user = await db.user.find_unique(where={"username": user_in.username})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    hashed_password = auth.get_password_hash(user_in.password)
    
    user = await db.user.create(
        data={
            "username": user_in.username,
            "password_hash": hashed_password,
            "first_name": user_in.firstName,
            "last_name": user_in.lastName,
        }
    )

    await db.account.create(
        data={
            "userId": user.id,
            "balance": round(1 + random.random() * 9999, 2)
        }
    )

    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/signin", response_model=schemas.Token)
async def signin(form_data: schemas.UserLogin):
    user = await db.user.find_unique(where={"username": form_data.username})
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


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
