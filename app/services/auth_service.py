import datetime
import secrets
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
from app.services.email_service import create_verification_token, send_security_alert
from app.utils.logger import logger


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


async def authenticate_user(
    username: str, password: str, ip_address: str, device_info: Dict[str, Any]
) -> Tuple[UserModel, str, str]:
    """사용자 인증 및 토큰 생성"""
    from app.services.session_service import create_session

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

    # 계정 잠금 확인
    if user.get("account_locked", False):
        locked_until = user.get("account_locked_until")
        current_time = datetime.datetime.now(datetime.timezone.utc)

        if locked_until and locked_until > current_time:
            # 계정이 여전히 잠겨있음
            remaining_minutes = int((locked_until - current_time).total_seconds() / 60)
            await log_auth_event(
                user_id=str(user["_id"]),
                username=user["username"],
                event_type="login_failed",
                ip_address=ip_address,
                device_info=device_info,
                status="failure",
                failure_reason="account_locked",
                details={"locked_until": locked_until.isoformat()},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"계정이 잠겼습니다. {remaining_minutes}분 후에 다시 시도해주세요.",
            )
        else:
            # 잠금 기간이 지났으면 잠금 해제
            await users_collection.update_one(
                {"_id": user["_id"]},
                {
                    "$set": {
                        "account_locked": False,
                        "account_locked_until": None,
                        "login_attempts": 0,
                    }
                },
            )

    if not verify_password(password, user["password_hash"]):
        # 로그인 실패 횟수 증가
        login_attempts = user.get("login_attempts", 0) + 1
        update_data = {
            "login_attempts": login_attempts,
            "last_failed_login": datetime.datetime.now(datetime.timezone.utc),
        }

        # 5회 이상 실패 시 계정 잠금 (30분)
        if login_attempts >= 5:
            locked_until = datetime.datetime.now(
                datetime.timezone.utc
            ) + datetime.timedelta(minutes=30)
            update_data.update(
                {"account_locked": True, "account_locked_until": locked_until}
            )

        await users_collection.update_one({"_id": user["_id"]}, {"$set": update_data})

        # 인증 실패 로그 기록
        await log_auth_event(
            user_id=str(user["_id"]),
            username=user["username"],
            event_type="login_failed",
            ip_address=ip_address,
            device_info=device_info,
            status="failure",
            failure_reason="invalid_password",
            details={"login_attempts": login_attempts},
        )

        if login_attempts >= 5:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="5회 이상 로그인에 실패하여 계정이 30분 동안 잠겼습니다.",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"잘못된 비밀번호입니다. ({login_attempts}/5회 실패)",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="계정이 비활성화되었습니다. 관리자에게 문의하세요.",
        )

    # 비밀번호 만료 확인
    if user.get("password_change_required", False):
        # 비밀번호 변경이 필요한 경우
        await log_auth_event(
            user_id=str(user["_id"]),
            username=user["username"],
            event_type="login_success",
            ip_address=ip_address,
            device_info=device_info,
            status="success",
            details={"password_change_required": True},
        )
        # 일단 로그인은 허용하고 클라이언트에서 비밀번호 변경 페이지로 안내하도록 정보 포함

    # 비밀번호 변경 날짜 확인 (90일 경과 시 변경 요구)
    password_last_changed = user.get("password_last_changed")
    if password_last_changed:
        days_since_change = (
            datetime.datetime.now(datetime.timezone.utc) - password_last_changed
        ).days
        if days_since_change >= 90:
            # 90일 이상 경과시 비밀번호 변경 필요로 표시
            await users_collection.update_one(
                {"_id": user["_id"]}, {"$set": {"password_change_required": True}}
            )
            # 클라이언트에서 처리할 수 있도록 정보 포함

    # 로그인 성공 시 login_attempts 초기화
    await users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"login_attempts": 0}, "$unset": {"last_failed_login": ""}},
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

    # 세션 생성
    session_id = await create_session(
        user_id=str(user["_id"]),
        ip_address=ip_address,
        device_info=device_info,
        refresh_token=refresh_token,
        access_token=access_token,
    )

    # 비정상 로그인 감지 및 알림
    await detect_suspicious_login(
        user_id=str(user["_id"]),
        username=user["username"],
        email=user["email"],
        ip_address=ip_address,
        device_info=device_info,
    )

    # 인증 성공 로그 기록
    await log_auth_event(
        user_id=str(user["_id"]),
        username=user["username"],
        event_type="login_success",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
        details={"session_id": session_id},
    )

    return UserModel(**user), access_token, refresh_token


async def detect_suspicious_login(
    user_id: str,
    username: str,
    email: str,
    ip_address: str,
    device_info: Dict[str, Any],
) -> None:
    """비정상 로그인 패턴 감지 및 알림"""

    auth_logs_collection = mongodb.get_auth_logs_db()

    # 최근 성공한 로그인 기록 조회 (최대 5개)
    recent_logins = (
        await auth_logs_collection.find(
            {"user_id": user_id, "event_type": "login_success", "status": "success"}
        )
        .sort("timestamp", -1)
        .limit(5)
        .to_list(length=5)
    )

    # 첫 로그인인 경우 알림 없음
    if not recent_logins or len(recent_logins) <= 1:
        return

    # 이전 로그인과 현재 로그인 비교
    previous_logins = recent_logins[1:]  # 방금 로그인한 기록 제외

    # 새로운 IP 주소 확인
    known_ips = {login["ip_address"] for login in previous_logins}
    new_ip = ip_address not in known_ips

    # 새로운 기기 확인
    def get_device_signature(device_info):
        return f"{device_info.get('device_type', '')}-{device_info.get('os', '')}-{device_info.get('browser', '')}"

    current_device = get_device_signature(device_info)
    known_devices = {
        get_device_signature(login["device_info"]) for login in previous_logins
    }
    new_device = current_device not in known_devices

    # 새로운 IP 또는 새로운 기기로 로그인한 경우 알림
    if new_ip or new_device:
        alert_type = []
        if new_ip:
            alert_type.append("새로운 IP 주소")
        if new_device:
            alert_type.append("새로운 기기")

        alert_message = f"{', '.join(alert_type)}에서 로그인이 감지되었습니다."

        # 보안 알림 이메일 발송
        await send_security_alert(
            email=email,
            username=username,
            ip_address=ip_address,
            device_info=device_info,
            alert_type=", ".join(alert_type),
            alert_message=alert_message,
        )

        # 알림 로그 기록
        await log_auth_event(
            user_id=user_id,
            username=username,
            event_type="security_alert",
            ip_address=ip_address,
            device_info=device_info,
            status="success",
            details={"alert_type": alert_type, "alert_message": alert_message},
        )


async def change_password(
    user_id: str,
    current_password: str,
    new_password: str,
    ip_address: str,
    device_info: Dict[str, Any],
) -> bool:
    """비밀번호 변경 (이전 비밀번호 재사용 방지 추가)"""
    from app.core.security import get_password_hash, verify_password

    users_collection = mongodb.get_users_db()
    user = await users_collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다."
        )

    # 현재 비밀번호 확인
    if not verify_password(current_password, user["password_hash"]):
        await log_auth_event(
            user_id=user_id,
            username=user["username"],
            event_type="password_change_failed",
            ip_address=ip_address,
            device_info=device_info,
            status="failure",
            failure_reason="invalid_current_password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="현재 비밀번호가 일치하지 않습니다.",
        )

    # 이전 비밀번호 목록 가져오기
    password_history = user.get("password_history", [])

    # 새 비밀번호가 이전 비밀번호와 동일한지 확인
    for old_hash in [user["password_hash"]] + password_history:
        if verify_password(new_password, old_hash):
            await log_auth_event(
                user_id=user_id,
                username=user["username"],
                event_type="password_change_failed",
                ip_address=ip_address,
                device_info=device_info,
                status="failure",
                failure_reason="password_reuse",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="최근 5개의 비밀번호는 재사용할 수 없습니다.",
            )

    # 새 비밀번호 해시
    new_password_hash = get_password_hash(new_password)

    # 비밀번호 이력에 현재 비밀번호 추가
    if password_history:
        # 최대 4개만 유지 (현재 비밀번호 + 4개 = 총 5개)
        password_history = [user["password_hash"]] + password_history[:4]
    else:
        password_history = [user["password_hash"]]

    # 사용자 정보 업데이트
    await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "password_hash": new_password_hash,
                "password_history": password_history,
                "password_last_changed": datetime.datetime.now(datetime.timezone.utc),
                "password_change_required": False,
                "updated_at": datetime.datetime.now(datetime.timezone.utc),
            }
        },
    )

    # 비밀번호 변경 성공 이벤트 기록
    await log_auth_event(
        user_id=user_id,
        username=user["username"],
        event_type="password_change",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
    )

    return True


async def create_password_reset_token(email: str) -> Optional[Tuple[str, str, str]]:
    """비밀번호 재설정 토큰 생성 및 저장"""
    users_collection = mongodb.get_users_db()

    # 이메일로 사용자 찾기
    user = await users_collection.find_one({"email": email, "is_active": True})
    if not user:
        return None

    # 랜덤 토큰 생성
    token = secrets.token_urlsafe(64)

    # 토큰 만료 시간 설정 (24시간)
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        hours=24
    )

    # 토큰 정보 저장
    await users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "password_reset_token": token,
                "password_reset_expires": expires,
                "updated_at": datetime.datetime.now(datetime.timezone.utc),
            }
        },
    )

    return token, user["username"], user["email"]


async def verify_reset_token_and_change_password(
    token: str, new_password: str, ip_address: str, device_info: Dict[str, Any]
) -> bool:
    """비밀번호 재설정 토큰 검증 및 비밀번호 변경"""
    from app.core.security import get_password_hash

    users_collection = mongodb.get_users_db()

    # 토큰으로 사용자 찾기
    user = await users_collection.find_one({"password_reset_token": token})
    if not user:
        return False

    # 토큰 만료 확인
    if user.get("password_reset_expires") < datetime.datetime.now(
        datetime.timezone.utc
    ):
        return False

    # 이전 비밀번호 목록 가져오기
    password_history = user.get("password_history", [])

    # 새 비밀번호가 이전 비밀번호와 동일한지 확인
    for old_hash in [user["password_hash"]] + password_history:
        if verify_password(new_password, old_hash):
            await log_auth_event(
                user_id=str(user["_id"]),
                username=user["username"],
                event_type="password_reset_failed",
                ip_address=ip_address,
                device_info=device_info,
                status="failure",
                failure_reason="password_reuse",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="최근 5개의 비밀번호는 재사용할 수 없습니다.",
            )

    # 새 비밀번호 해시
    new_password_hash = get_password_hash(new_password)

    # 비밀번호 이력에 현재 비밀번호 추가
    if password_history:
        # 최대 4개만 유지 (현재 비밀번호 + 4개 = 총 5개)
        password_history = [user["password_hash"]] + password_history[:4]
    else:
        password_history = [user["password_hash"]]

    # 사용자 정보 업데이트
    now = datetime.datetime.now(datetime.timezone.utc)
    await users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "password_hash": new_password_hash,
                "password_history": password_history,
                "password_last_changed": now,
                "password_change_required": False,
                "updated_at": now,
                "account_locked": False,  # 계정이 잠겼을 경우 해제
                "login_attempts": 0,  # 로그인 시도 초기화
            },
            "$unset": {"password_reset_token": "", "password_reset_expires": ""},
        },
    )

    # 이벤트 로깅
    await log_auth_event(
        user_id=str(user["_id"]),
        username=user["username"],
        event_type="password_reset",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
    )

    return True
