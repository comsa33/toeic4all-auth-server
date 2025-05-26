import datetime
import uuid
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt

from app.api.dependencies import get_current_user, get_user_ip_and_device_info
from app.core.config import settings
from app.db.mongodb import mongodb
from app.db.redis_client import redis_client
from app.schemas.auth import (
    ChangePasswordRequest,
    DeleteAccountRequest,
    LoginRequest,
    LoginResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshTokenRequest,
    Token,
    UnlockAccountRequest,
)
from app.schemas.session import SessionListResponse, SessionResponse
from app.schemas.user import UserCreate, UserMeResponse, UserProfileBase, UserResponse
from app.services.auth_service import (
    authenticate_user,
    change_password,
    create_password_reset_token,
    create_user,
    delete_user_account,
    log_auth_event,
    logout_user,
    refresh_access_token,
    verify_reset_token_and_change_password,
)
from app.services.email_service import (
    create_verification_token,
    send_password_reset_email,
    verify_email_token,
)
from app.services.session_service import (
    get_user_sessions,
    terminate_all_sessions_except_current,
    terminate_session,
)
from app.utils.password_utils import validate_password_strength

router = APIRouter()


@router.get("/me", response_model=UserMeResponse)
async def get_current_user_info(
    request: Request,
    current_user: Dict = Depends(get_current_user),
):
    """현재 로그인된 사용자 정보 조회 (자동 로그인용)"""

    # 사용자 정보를 응답 모델에 맞게 변환
    user_info = {
        "id": str(current_user["_id"]),
        "username": current_user["username"],
        "email": current_user["email"],
        "profile": current_user.get("profile", {}),
        "role": current_user.get("role", "user"),
        "created_at": current_user["created_at"],
        "updated_at": current_user.get("updated_at"),
        "last_login": current_user.get("last_login"),
        "is_active": current_user.get("is_active", True),
        # 추가 정보 (모바일 앱에서 필요한 경우)
        "subscription": current_user.get("subscription"),
        "stats": current_user.get("stats"),
        "is_email_verified": current_user.get("is_email_verified", False),
        "password_change_required": current_user.get("password_change_required", False),
    }

    return user_info


@router.get("/me/profile", response_model=UserProfileBase)
async def get_current_user_profile(
    current_user: Dict = Depends(get_current_user),
):
    """현재 사용자의 프로필 정보만 조회"""
    return current_user.get("profile", {})


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    login_data: LoginRequest,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """사용자 로그인 및 토큰 생성"""
    ip_address, device_info = ip_and_device
    user, access_token, refresh_token = await authenticate_user(
        username=login_data.username,
        password=login_data.password,
        ip_address=ip_address,
        device_info=device_info,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user_id": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }


@router.post("/login/oauth2", response_model=Token)
async def login_oauth2(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """OAuth2 호환 로그인 엔드포인트"""
    ip_address, device_info = ip_and_device
    user, access_token, refresh_token = await authenticate_user(
        username=form_data.username,
        password=form_data.password,
        ip_address=ip_address,
        device_info=device_info,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register(
    request: Request,
    user_data: UserCreate,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """새 사용자 등록"""
    ip_address, device_info = ip_and_device
    user = await create_user(
        user_data=user_data.model_dump(exclude={"confirm_password"}),
        ip_address=ip_address,
        device_info=device_info,
    )

    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        profile=user.profile.model_dump(),
        role=user.role,
        created_at=user.created_at,
        updated_at=user.updated_at,
        is_active=user.is_active,
    )


@router.post("/refresh-token", response_model=Token)
async def refresh_token(request: Request, refresh_data: RefreshTokenRequest):
    """리프레시 토큰을 사용하여 새 액세스 토큰 생성"""
    access_token, refresh_token = await refresh_access_token(refresh_data.refresh_token)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    refresh_data: RefreshTokenRequest,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """사용자 로그아웃 및 토큰 무효화"""

    ip_address, device_info = ip_and_device

    try:
        # 토큰에서 사용자 ID 추출
        payload = jwt.decode(
            refresh_data.refresh_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )
        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="유효하지 않은 토큰입니다.",
            )

        await logout_user(
            user_id=user_id,
            refresh_token=refresh_data.refresh_token,
            ip_address=ip_address,
            device_info=device_info,
        )

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="유효하지 않은 토큰입니다."
        )


@router.post("/password-reset/request", status_code=status.HTTP_202_ACCEPTED)
async def request_password_reset(
    request: Request,
    reset_data: PasswordResetRequest,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """비밀번호 재설정 요청"""
    ip_address, device_info = ip_and_device

    # 토큰 생성 및 이메일 발송
    result = await create_password_reset_token(reset_data.email)

    # 항상 성공 응답 반환 (이메일 존재 여부 노출 방지)
    if result:
        token, username, email = result

        # 이메일 발송
        email_sent = await send_password_reset_email(email, username, token)

        # 이벤트 로깅
        await log_auth_event(
            user_id=None,  # 사용자 ID는 로그에 남기지 않음 (보안상)
            username=username,
            event_type="password_reset_request",
            ip_address=ip_address,
            device_info=device_info,
            status="success" if email_sent else "failure",
            failure_reason=None if email_sent else "email_sending_failed",
        )

    # 성공 여부와 관계없이 동일한 응답 반환
    return {"message": "비밀번호 재설정 링크를 이메일로 전송했습니다."}


@router.post("/password-reset/confirm", status_code=status.HTTP_200_OK)
async def confirm_password_reset(
    request: Request,
    reset_data: PasswordResetConfirm,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """비밀번호 재설정 확인 및 변경"""
    ip_address, device_info = ip_and_device

    # 비밀번호 확인 일치 검사
    if reset_data.new_password != reset_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="새 비밀번호와 확인 비밀번호가 일치하지 않습니다.",
        )

    # 비밀번호 정책 검사
    is_valid, error_msg = validate_password_strength(reset_data.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    # 토큰 검증 및 비밀번호 변경
    success = await verify_reset_token_and_change_password(
        token=reset_data.token,
        new_password=reset_data.new_password,
        ip_address=ip_address,
        device_info=device_info,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="유효하지 않거나 만료된 비밀번호 재설정 링크입니다.",
        )

    return {"message": "비밀번호가 성공적으로 변경되었습니다."}


@router.post("/password-change", status_code=status.HTTP_200_OK)
async def change_password_endpoint(
    request: Request,
    password_data: ChangePasswordRequest,
    current_user: Dict = Depends(get_current_user),
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """비밀번호 변경"""
    # 소셜 로그인 사용자 확인 및 제한 추가
    has_social_connections = bool(current_user.get("social_connections", {}))
    if has_social_connections:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="소셜 로그인 사용자는 비밀번호를 변경할 수 없습니다.",
        )

    ip_address, device_info = ip_and_device

    if password_data.new_password != password_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="새 비밀번호와 확인 비밀번호가 일치하지 않습니다.",
        )

    # 비밀번호 정책 검사
    is_valid, error_msg = validate_password_strength(password_data.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error_msg)

    await change_password(
        user_id=str(current_user["_id"]),
        current_password=password_data.current_password,
        new_password=password_data.new_password,
        ip_address=ip_address,
        device_info=device_info,
    )

    return {"message": "비밀번호가 성공적으로 변경되었습니다."}


@router.get("/verify-email", status_code=status.HTTP_200_OK)
async def verify_email(
    token: str = Query(..., description="이메일 인증 토큰"),
):
    """이메일 인증 처리"""

    success = await verify_email_token(token)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="유효하지 않거나 만료된 인증 토큰입니다.",
        )

    return {"message": "이메일 인증이 완료되었습니다."}


@router.post("/resend-verification", status_code=status.HTTP_200_OK)
async def resend_verification(
    current_user: Dict = Depends(get_current_user),
):
    """이메일 인증 메일 재발송"""
    # 이미 인증된 경우
    if current_user.get("is_email_verified", False):
        return {"message": "이미 인증된 이메일입니다."}

    success = await create_verification_token(
        str(current_user["_id"]), current_user["email"], current_user["username"]
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="이메일 발송 중 오류가 발생했습니다.",
        )

    return {"message": "인증 이메일이 성공적으로 재발송되었습니다."}


@router.post("/delete-account", status_code=status.HTTP_200_OK)
async def delete_account(
    request: Request,
    delete_data: DeleteAccountRequest,
    current_user: Dict = Depends(get_current_user),
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """사용자 계정 삭제"""
    ip_address, device_info = ip_and_device

    # 소셜 로그인 사용자인 경우 비밀번호 확인 생략
    has_social_connections = bool(current_user.get("social_connections", {}))
    password = None if has_social_connections else delete_data.password

    await delete_user_account(
        user_id=str(current_user["_id"]),
        password=password,
        ip_address=ip_address,
        device_info=device_info,
    )

    return {"message": "계정이 성공적으로 삭제되었습니다."}


@router.get("/sessions", response_model=SessionListResponse)
async def list_active_sessions(
    request: Request,
    current_user: Dict = Depends(get_current_user),
):
    """사용자의 활성 세션 목록 조회"""
    sessions = await get_user_sessions(str(current_user["_id"]))

    # 세션 목록을 응답 모델에 맞게 변환
    session_list = []
    for session in sessions:
        session_list.append(
            SessionResponse(
                session_id=session.session_id,
                device_info=session.device_info,
                ip_address=session.ip_address,
                login_time=session.login_time,
                is_current=request.headers.get("Authorization", "").endswith(
                    session.access_token or ""
                ),
            )
        )

    return {"sessions": session_list}


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: str,
    request: Request,
    current_user: Dict = Depends(get_current_user),
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """특정 세션 종료 (원격 로그아웃)"""
    ip_address, device_info = ip_and_device

    # 세션 종료
    success = await terminate_session(str(current_user["_id"]), session_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="세션을 찾을 수 없습니다."
        )

    # 이벤트 로깅
    await log_auth_event(
        user_id=str(current_user["_id"]),
        username=current_user["username"],
        event_type="session_terminated",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
        details={"terminated_session_id": session_id},
    )


@router.delete("/sessions", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_all_other_sessions(
    request: Request,
    current_user: Dict = Depends(get_current_user),
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """현재 세션을 제외한 모든 세션 종료"""
    ip_address, device_info = ip_and_device

    # 현재 세션 ID 확인
    auth_header = request.headers.get("Authorization", "")
    current_token = (
        auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""
    )

    # Redis에서 현재 토큰에 해당하는 세션 ID 찾기
    redis = redis_client.get_client()
    session_ids = redis.smembers(f"user_sessions:{str(current_user['_id'])}")

    current_session_id = None
    for session_id in session_ids:
        session_data = redis.get(f"session:{current_user['_id']}:{session_id}")
        if session_data and current_token in session_data:
            current_session_id = session_id
            break

    if not current_session_id:
        # 현재 세션을 찾을 수 없는 경우, 새 세션 ID 생성

        current_session_id = str(uuid.uuid4())

    # 다른 모든 세션 종료
    terminated_count = await terminate_all_sessions_except_current(
        str(current_user["_id"]), current_session_id
    )

    # 이벤트 로깅
    await log_auth_event(
        user_id=str(current_user["_id"]),
        username=current_user["username"],
        event_type="all_sessions_terminated",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
        details={"terminated_count": terminated_count},
    )


@router.get("/password-status", status_code=status.HTTP_200_OK)
async def check_password_status(
    current_user: Dict = Depends(get_current_user),
):
    """비밀번호 상태 확인 (만료 여부 등)"""
    # 비밀번호 변경 필요 여부
    password_change_required = current_user.get("password_change_required", False)

    # 비밀번호 변경 날짜 확인
    password_last_changed = current_user.get("password_last_changed")
    days_since_change = None

    if password_last_changed:
        days_since_change = (
            datetime.datetime.now(datetime.timezone.utc) - password_last_changed
        ).days

    return {
        "password_change_required": password_change_required,
        "password_last_changed": password_last_changed,
        "days_since_change": days_since_change,
        "days_until_expiry": (
            max(0, 90 - (days_since_change or 0))
            if days_since_change is not None
            else None
        ),
    }


@router.post("/unlock-account", status_code=status.HTTP_200_OK)
async def unlock_account(
    request: Request,
    unlock_data: UnlockAccountRequest,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """계정 잠금 해제 (관리자용)"""
    ip_address, device_info = ip_and_device

    # 관리자 권한 확인 로직 구현 필요

    users_collection = mongodb.get_users_db()
    user = await users_collection.find_one({"username": unlock_data.username})

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다."
        )

    # 계정 잠금 해제
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

    # 이벤트 로깅
    await log_auth_event(
        user_id=str(user["_id"]),
        username=user["username"],
        event_type="account_unlock",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
        details={"unlocked_by": unlock_data.admin_username},
    )

    return {"message": f"{unlock_data.username} 계정의 잠금이 해제되었습니다."}
