import datetime
from typing import Annotated, Any, Dict, List, Optional

from bson import ObjectId
from pydantic import BaseModel, BeforeValidator, Field


# 간단한 방식으로 ObjectId 처리
def validate_object_id(v: Any) -> ObjectId:
    if isinstance(v, ObjectId):
        return v
    if isinstance(v, str) and ObjectId.is_valid(v):
        return ObjectId(v)
    raise ValueError("올바른 ObjectId가 아닙니다")


# Pydantic v2 스타일로 타입 정의
PyObjectId = Annotated[ObjectId, BeforeValidator(validate_object_id)]


class DeviceInfoModel(BaseModel):
    device_type: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    browser: Optional[str] = None
    app_version: Optional[str] = None


class LocationModel(BaseModel):
    country: Optional[str] = None
    city: Optional[str] = None
    coordinates: Optional[List[float]] = None


class AuthLogModel(BaseModel):
    id: PyObjectId = Field(default_factory=ObjectId, alias="_id")
    user_id: Optional[str] = None
    username: Optional[str] = None
    event_type: str
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    ip_address: str
    device_info: DeviceInfoModel = Field(default_factory=DeviceInfoModel)
    location: Optional[LocationModel] = None
    status: str = "success"
    failure_reason: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None

    model_config = {
        "arbitrary_types_allowed": True,
        "populate_by_name": True,
        "json_encoders": {ObjectId: str},
    }
