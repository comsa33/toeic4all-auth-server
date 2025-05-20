from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, EmailStr, Field


# 간단한 방식으로 ObjectId 처리
def validate_object_id(v: Any) -> ObjectId:
    if isinstance(v, ObjectId):
        return v
    if isinstance(v, str) and ObjectId.is_valid(v):
        return ObjectId(v)
    raise ValueError("올바른 ObjectId가 아닙니다")


# Pydantic v2 스타일로 타입 정의
PyObjectId = Annotated[ObjectId, BeforeValidator(validate_object_id)]


class UserProfileModel(BaseModel):
    full_name: Optional[str] = None
    profile_image: Optional[str] = None
    bio: Optional[str] = None
    preferences: Dict = Field(default_factory=dict)


class UserSubscriptionModel(BaseModel):
    plan: Optional[str] = "free"
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    is_active: bool = True
    payment_id: Optional[str] = None


class UserStatsModel(BaseModel):
    part5_correct: int = 0
    part5_total: int = 0
    part6_correct: int = 0
    part6_total: int = 0
    part7_correct: int = 0
    part7_total: int = 0
    last_activity: Optional[datetime] = None
    streak_days: int = 0


class UserModel(BaseModel):
    id: PyObjectId = Field(default_factory=ObjectId, alias="_id")
    username: str
    email: EmailStr
    password_hash: str
    profile: UserProfileModel = Field(default_factory=UserProfileModel)
    stats: UserStatsModel = Field(default_factory=UserStatsModel)
    subscription: UserSubscriptionModel = Field(default_factory=UserSubscriptionModel)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    refresh_token: Optional[str] = None
    is_active: bool = True
    role: str = "user"
    social_connections: Dict = Field(default_factory=dict)

    # 로그인 보안 관련 추가 필드
    login_attempts: int = 0
    last_failed_login: Optional[datetime] = None
    account_locked: bool = False
    account_locked_until: Optional[datetime] = None

    # 비밀번호 정책 관련 추가 필드
    password_last_changed: datetime = Field(default_factory=datetime.utcnow)
    password_history: List[str] = Field(default_factory=list)
    password_change_required: bool = False

    model_config = {
        "arbitrary_types_allowed": True,
        "populate_by_name": True,
        "json_encoders": {ObjectId: str},
    }
