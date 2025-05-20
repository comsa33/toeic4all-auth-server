import re
from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


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
        assert re.match(
            r"^[a-zA-Z0-9_-]+$", v
        ), "사용자 이름은 알파벳, 숫자, 밑줄, 하이픈만 포함할 수 있습니다."
        assert len(v) >= 3, "사용자 이름은 최소 3자 이상이어야 합니다."
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        assert len(v) >= 8, "비밀번호는 최소 8자 이상이어야 합니다."
        assert re.search(
            r"[A-Z]", v
        ), "비밀번호는 최소 1개 이상의 대문자를 포함해야 합니다."
        assert re.search(
            r"[a-z]", v
        ), "비밀번호는 최소 1개 이상의 소문자를 포함해야 합니다."
        assert re.search(
            r"[0-9]", v
        ), "비밀번호는 최소 1개 이상의 숫자를 포함해야 합니다."
        assert re.search(
            r"[^A-Za-z0-9]", v
        ), "비밀번호는 최소 1개 이상의 특수문자를 포함해야 합니다."
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
