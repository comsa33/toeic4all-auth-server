from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.utils.password_utils import validate_password_strength, validate_username


class UserProfileBase(BaseModel):
    full_name: Optional[str] = None
    profile_image: Optional[str] = None
    bio: Optional[str] = None
    preferences: Dict = Field(default_factory=dict)


class UserPreferences(BaseModel):
    notification_enabled: bool = True
    theme: str = "light"
    language: str = "ko"


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        is_valid, error_msg = validate_username(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        is_valid, error_msg = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("비밀번호가 일치하지 않습니다.")
        return v


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    profile: Optional[UserProfileBase] = None


class UserInDB(BaseModel):
    id: str
    username: str
    email: EmailStr
    profile: UserProfileBase
    is_active: bool
    role: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None


class UserResponse(BaseModel):
    id: str
    username: str
    email: EmailStr
    profile: UserProfileBase
    role: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    is_active: bool
