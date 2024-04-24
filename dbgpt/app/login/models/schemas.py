from pydantic import BaseModel


class UserBase(BaseModel):
    username: str


class User(UserBase):
    id: int
    disabled: bool

    class Config:
        orm_mode = True


class UserInDB(User):
    hashed_password: str
