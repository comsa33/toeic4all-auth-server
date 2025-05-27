from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None
    role: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    confirm_password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    email: str
    role: str


class DeleteAccountRequest(BaseModel):
    password: Optional[str] = None  # 일반 로그인 사용자 확인용
    confirm_text: str  # "회원탈퇴" 문구 확인용

    @field_validator("confirm_text")
    @classmethod
    def validate_confirm_text(cls, v: str) -> str:
        if v != "회원탈퇴":
            raise ValueError("'회원탈퇴'를 정확히 입력해주세요.")
        return v


class UnlockAccountRequest(BaseModel):
    username: str
    admin_username: str
    reason: Optional[str] = None


class GoogleMobileLoginRequest(BaseModel):
    id_token: str
    access_token: Optional[str] = None


class KakaoMobileLoginRequest(BaseModel):
    access_token: str


class NaverMobileLoginRequest(BaseModel):
    access_token: str
