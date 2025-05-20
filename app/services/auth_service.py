import datetime
from typing import Any, Dict, Optional, Tuple

from bson.objectid import ObjectId
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    get_password_hash,
    verify_password,
)
from app.db.mongodb import mongodb
from app.db.redis_client import redis_client
from app.models.user import UserModel
from app.services.email_service import create_verification_token
from app.utils.logger import logger


async def authenticate_user(
    username: str, password: str, ip_address: str, device_info: Dict[str, Any]
) -> Tuple[UserModel, str, str]:
    """사용자 인증 및 토큰 생성"""
    users_collection = mongodb.get_users_db()
    user = await users_collection.find_one(
        {"$or": [{"username": username}, {"email": username}]}
    )

    if not user:
        # 인증 실패 로그 기록
        await log_auth_event(
            user_id=None,
            username=username,
            event_type="login_failed",
            ip_address=ip_address,
            device_info=device_info,
            status="failure",
            failure_reason="user_not_found",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="잘못된 사용자 이름 또는 이메일입니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not verify_password(password, user["password_hash"]):
        # 인증 실패 로그 기록
        await log_auth_event(
            user_id=str(user["_id"]),
            username=user["username"],
            event_type="login_failed",
            ip_address=ip_address,
            device_info=device_info,
            status="failure",
            failure_reason="invalid_password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="잘못된 비밀번호입니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="계정이 비활성화되었습니다. 관리자에게 문의하세요.",
        )

    # 액세스 토큰 및 리프레시 토큰 생성
    access_token = create_access_token(
        subject=str(user["_id"]), role=user.get("role", "user")
    )
    refresh_token = create_refresh_token(
        subject=str(user["_id"]), role=user.get("role", "user")
    )

    # 사용자 정보 업데이트 (마지막 로그인 시간, 리프레시 토큰)
    await users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "last_login": datetime.datetime.now(datetime.timezone.utc),
                "refresh_token": refresh_token,
            }
        },
    )

    # 인증 성공 로그 기록
    await log_auth_event(
        user_id=str(user["_id"]),
        username=user["username"],
        event_type="login_success",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
    )

    return UserModel(**user), access_token, refresh_token


async def refresh_access_token(refresh_token: str) -> Tuple[str, str]:
    """리프레시 토큰을 사용하여 새 액세스 토큰 생성"""
    from jose import JWTError, jwt

    try:
        # 리프레시 토큰 검증
        payload = jwt.decode(
            refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        user_id = payload.get("sub")
        role = payload.get("role")
        token_type = payload.get("token_type")

        if not user_id or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="유효하지 않은 리프레시 토큰입니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Redis에서 블랙리스트된 토큰인지 확인
        redis = redis_client.get_client()
        if redis.exists(f"blacklist:{refresh_token}"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="만료된 토큰입니다. 다시 로그인해주세요.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 데이터베이스에서 사용자 확인
        users_collection = mongodb.get_users_db()
        user = await users_collection.find_one(
            {"_id": ObjectId(user_id), "refresh_token": refresh_token}
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="유효하지 않은 사용자 또는 리프레시 토큰입니다.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 새 액세스 토큰 생성
        new_access_token = create_access_token(subject=user_id, role=role)
        new_refresh_token = create_refresh_token(subject=user_id, role=role)

        # 사용자 정보 업데이트 (새 리프레시 토큰)
        await users_collection.update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"refresh_token": new_refresh_token}}
        )

        # 기존 리프레시 토큰을 블랙리스트에 추가
        jwt_payload = jwt.decode(
            refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_exp": False},
        )
        exp = jwt_payload.get("exp", 0)
        current_timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
        ttl = max(0, int(exp - current_timestamp))

        if ttl > 0:
            redis.setex(f"blacklist:{refresh_token}", ttl, "1")

        return new_access_token, new_refresh_token

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 리프레시 토큰입니다.",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def logout_user(
    user_id: str, refresh_token: str, ip_address: str, device_info: Dict[str, Any]
) -> None:
    """사용자 로그아웃 처리"""
    from jose import JWTError, jwt

    try:
        # 리프레시 토큰 검증
        jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        # 데이터베이스에서 리프레시 토큰 제거
        users_collection = mongodb.get_users_db()
        await users_collection.update_one(
            {"_id": ObjectId(user_id)}, {"$set": {"refresh_token": None}}
        )

        # 리프레시 토큰을 블랙리스트에 추가
        redis = redis_client.get_client()

        try:
            jwt_payload = jwt.decode(
                refresh_token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={"verify_exp": False},
            )
            exp = jwt_payload.get("exp", 0)
            current_timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
            ttl = max(0, int(exp - current_timestamp))

            if ttl > 0:
                redis.setex(f"blacklist:{refresh_token}", ttl, "1")
        except JWTError:
            # 토큰이 이미 만료되었더라도 로그아웃 처리
            pass

        # 로그아웃 이벤트 기록
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        if user:
            await log_auth_event(
                user_id=user_id,
                username=user.get("username", ""),
                event_type="logout",
                ip_address=ip_address,
                device_info=device_info,
                status="success",
            )

    except Exception as e:
        logger.error(f"로그아웃 처리 중 오류 발생: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="로그아웃 처리 중 오류가 발생했습니다.",
        )


async def create_user(
    user_data: Dict[str, Any], ip_address: str, device_info: Dict[str, Any]
) -> UserModel:
    """새 사용자 생성"""
    users_collection = mongodb.get_users_db()

    # 사용자 이름 또는 이메일 중복 확인
    existing_user = await users_collection.find_one(
        {"$or": [{"username": user_data["username"]}, {"email": user_data["email"]}]}
    )

    if existing_user:
        field = (
            "username"
            if existing_user["username"] == user_data["username"]
            else "email"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"이미 사용 중인 {field}입니다.",
        )

    # 비밀번호 해시화
    hashed_password = get_password_hash(user_data["password"])

    # 새 사용자 데이터 준비
    new_user = {
        "username": user_data["username"],
        "email": user_data["email"],
        "password_hash": hashed_password,
        "profile": user_data.get("profile", {}),
        "stats": {
            "part5_correct": 0,
            "part5_total": 0,
            "part6_correct": 0,
            "part6_total": 0,
            "part7_correct": 0,
            "part7_total": 0,
            "last_activity": datetime.datetime.now(datetime.timezone.utc),
            "streak_days": 0,
        },
        "subscription": {
            "plan": "free",
            "start_date": datetime.datetime.now(datetime.timezone.utc),
            "end_date": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=30),
            "is_active": True,
            "payment_id": "",
        },
        "created_at": datetime.datetime.now(datetime.timezone.utc),
        "updated_at": datetime.datetime.now(datetime.timezone.utc),
        "last_login": datetime.datetime.now(datetime.timezone.utc),
        "refresh_token": "",
        "is_active": True,
        "role": "user",
        "social_connections": {},
    }

    # 데이터베이스에 사용자 저장
    result = await users_collection.insert_one(new_user)
    new_user["_id"] = result.inserted_id

    # 이메일 인증 토큰 생성 및 이메일 발송 (비동기로 처리)
    await create_verification_token(
        str(result.inserted_id), new_user["email"], new_user["username"]
    )

    # 회원가입 이벤트 기록
    await log_auth_event(
        user_id=str(result.inserted_id),
        username=new_user["username"],
        event_type="signup",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
    )

    return UserModel(**new_user)


async def log_auth_event(
    user_id: Optional[str],
    username: Optional[str],
    event_type: str,
    ip_address: str,
    device_info: Dict[str, Any],
    status: str,
    failure_reason: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
) -> None:
    """인증 이벤트 로깅"""
    auth_logs_collection = mongodb.get_auth_logs_db()

    log_entry = {
        "user_id": user_id,
        "username": username,
        "event_type": event_type,
        "timestamp": datetime.datetime.now(datetime.timezone.utc),
        "ip_address": ip_address,
        "device_info": {
            **device_info,
            "app_version": device_info.get("app_version") or "",
        },
        "status": status,
        "failure_reason": failure_reason or "",
        "details": details or {},
        "session_id": session_id or "",
    }

    try:
        await auth_logs_collection.insert_one(log_entry)
    except Exception as e:
        logger.error(f"인증 로그 저장 중 오류 발생: {e}")


async def delete_user_account(
    user_id: str,
    password: Optional[str] = None,
    ip_address: Optional[str] = None,
    device_info: Optional[Dict[str, Any]] = None,
) -> bool:
    """사용자 계정 삭제 처리"""
    users_collection = mongodb.get_users_db()
    user = await users_collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다."
        )

    # 일반 로그인 사용자인 경우 비밀번호 확인
    has_social = bool(user.get("social_connections", {}))
    if not has_social and password:
        if not verify_password(password, user["password_hash"]):
            # 인증 실패 로그 기록
            await log_auth_event(
                user_id=str(user["_id"]),
                username=user["username"],
                event_type="account_delete_failed",
                ip_address=ip_address,
                device_info=device_info,
                status="failure",
                failure_reason="invalid_password",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="비밀번호가 일치하지 않습니다.",
            )

    # 계정 삭제 전 로그아웃 처리 (토큰 블랙리스트에 추가)
    if user.get("refresh_token"):
        try:
            await logout_user(
                user_id=user_id,
                refresh_token=user["refresh_token"],
                ip_address=ip_address,
                device_info=device_info,
            )
        except Exception as e:
            logger.warning(f"회원탈퇴 중 로그아웃 처리 오류: {e}")

    # GDPR 등 개인정보보호를 위한 소프트 삭제 및 익명화 처리
    anonymous_data = {
        "username": f"deleted_{str(user['_id'])}",
        "email": f"deleted_{str(user['_id'])}@deleted.user",
        "password_hash": None,
        "profile": {
            "full_name": None,
            "profile_image": None,
            "bio": None,
            "preferences": {},
        },
        "is_active": False,
        "is_deleted": True,
        "deleted_at": datetime.datetime.now(datetime.timezone.utc),
        "refresh_token": None,
        "social_connections": {},
    }

    # 계정 익명화 처리
    await users_collection.update_one(
        {"_id": ObjectId(user_id)}, {"$set": anonymous_data}
    )

    # 탈퇴 이벤트 로깅
    await log_auth_event(
        user_id=user_id,
        username=user["username"],
        event_type="account_deleted",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
    )

    # Redis에 저장된 토큰 정보 삭제
    redis = redis_client.get_client()
    key_pattern = f"*:{user_id}:*"
    for key in redis.keys(key_pattern):
        redis.delete(key)

    return True
