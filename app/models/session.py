from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel


class SessionModel(BaseModel):
    session_id: str
    user_id: str
    device_info: Dict
    ip_address: str
    login_time: datetime
    expires_at: datetime
    is_active: bool = True
    refresh_token: str
    access_token: Optional[str] = None
