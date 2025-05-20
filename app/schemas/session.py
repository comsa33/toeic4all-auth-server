from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel


class SessionResponse(BaseModel):
    session_id: str
    device_info: Dict
    ip_address: str
    login_time: datetime
    is_current: bool


class SessionListResponse(BaseModel):
    sessions: List[SessionResponse]


class UnlockAccountRequest(BaseModel):
    username: str
    admin_username: str
    reason: Optional[str] = None
