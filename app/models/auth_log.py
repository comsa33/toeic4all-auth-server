from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pydantic import BaseModel, Field


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
    def __get_pydantic_json_schema__(cls, field_schema):
        field_schema.update(type="string")


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
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    user_id: Optional[str] = None
    username: Optional[str] = None
    event_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip_address: str
    device_info: DeviceInfoModel = Field(default_factory=DeviceInfoModel)
    location: Optional[LocationModel] = None
    status: str = "success"
    failure_reason: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    session_id: Optional[str] = None

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}
