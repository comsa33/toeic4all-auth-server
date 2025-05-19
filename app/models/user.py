from datetime import datetime
from typing import Dict, Optional

from bson import ObjectId
from pydantic import BaseModel, EmailStr, Field


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("유효하지 않은 ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


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
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
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

    # 소셜 로그인 정보
    social_connections: Dict = Field(default_factory=dict)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
