import re
from typing import Any, Dict, Tuple

from bson import ObjectId
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from app.core.config import settings
from app.db.mongodb import mongodb
from app.db.redis_client import redis_client
from app.schemas.auth import TokenPayload

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_PREFIX}/auth/login/oauth2"
)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """현재 인증된 사용자 가져오기"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="인증할 수 없습니다",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # 토큰 디코딩
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenPayload(**payload)
    except JWTError:
        raise credentials_exception

    # Redis에서 블랙리스트된 토큰인지 확인
    redis = redis_client.get_client()
    if redis.exists(f"blacklist:{token}"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="만료된 토큰입니다. 다시 로그인해주세요.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 사용자 정보 가져오기
    users_collection = mongodb.get_users_db()
    user = await users_collection.find_one({"_id": ObjectId(token_data.sub)})

    if user is None:
        raise credentials_exception

    return user


async def get_user_ip_and_device_info(request: Request) -> Tuple[str, Dict[str, Any]]:
    """사용자 IP 주소 및 장치 정보 가져오기"""
    # IP 주소 가져오기
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()
    else:
        ip_address = request.client.host

    # User-Agent 파싱
    user_agent = request.headers.get("User-Agent", "")

    # 모바일 기기 확인
    is_mobile = bool(re.search(r"Mobile|Android|iPhone|iPad", user_agent))

    # OS 확인
    os_info = "Unknown"
    os_version = ""

    if "Windows" in user_agent:
        os_info = "Windows"
        match = re.search(r"Windows NT (\d+\.\d+)", user_agent)
        if match:
            os_version = match.group(1)
    elif "Mac OS X" in user_agent:
        os_info = "macOS"
        match = re.search(r"Mac OS X (\d+[._]\d+[._]\d+)", user_agent)
        if match:
            os_version = match.group(1).replace("_", ".")
    elif "Android" in user_agent:
        os_info = "Android"
        match = re.search(r"Android (\d+\.\d+)", user_agent)
        if match:
            os_version = match.group(1)
    elif "iOS" in user_agent or "iPhone OS" in user_agent:
        os_info = "iOS"
        match = re.search(r"OS (\d+[._]\d+[._]?\d*)", user_agent)
        if match:
            os_version = match.group(1).replace("_", ".")
    elif "Linux" in user_agent:
        os_info = "Linux"

    # 브라우저 확인
    browser_info = "Unknown"

    if "Chrome" in user_agent and "Edg" not in user_agent and "OPR" not in user_agent:
        browser_info = "Chrome"
    elif "Firefox" in user_agent:
        browser_info = "Firefox"
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        browser_info = "Safari"
    elif "Edg" in user_agent:
        browser_info = "Edge"
    elif "OPR" in user_agent or "Opera" in user_agent:
        browser_info = "Opera"

    # 앱 버전 (모바일 앱인 경우, 가정)
    app_version = None
    match = re.search(r"TOEIC4ALL/(\d+\.\d+\.\d+)", user_agent)
    if match:
        app_version = match.group(1)

    device_info = {
        "device_type": "mobile" if is_mobile else "desktop",
        "os": os_info,
        "os_version": os_version,
        "browser": browser_info,
        "app_version": app_version,
    }

    return ip_address, device_info


def get_admin_user(user=Depends(get_current_user)):
    """관리자 권한 확인"""
    if user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="권한이 없습니다"
        )
    return user
