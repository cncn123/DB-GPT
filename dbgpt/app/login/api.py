import logging

from fastapi import APIRouter

from dbgpt._private.config import Config

from datetime import timedelta

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

from sqlalchemy.orm import Session

from . import crud
from dbgpt.app.login.models import schemas
from .crud import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token
from .database import SessionLocal
from dbgpt.app.login.models.token import Token

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.propagate = True
CFG = Config()
router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# get the token for the user
@router.post("/token")
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
) -> Token:
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    logger.info("User: %s", user)
    if user is None:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


# get the current user
@router.get("/users/me", response_model=schemas.User)
async def read_users_me(
        db: Session = Depends(get_db),
        current_user: schemas.User = Depends(crud.get_current_active_user),
):
    logger.info("Current User: %s", current_user)
    return current_user


# check if the user is in the database
@router.get("/users/{username}", response_model=schemas.User)
async def find_user(
        username: str, db: Session = Depends(get_db)
):
    db_user = crud.get_user(db, username=username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


# create a new user
@router.post("/register", response_model=schemas.User)
async def register_new_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)
