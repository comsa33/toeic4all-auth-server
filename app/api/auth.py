from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.dependencies import get_current_user, get_user_ip_and_device_info
from app.schemas.auth import (
    ChangePasswordRequest,
    DeleteAccountRequest,
    LoginRequest,
    LoginResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshTokenRequest,
    Token,
)
from app.schemas.user import UserCreate, UserResponse
from app.services.auth_service import (
    authenticate_user,
    create_user,
    delete_user_account,
    logout_user,
    refresh_access_token,
)

router = APIRouter()


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
    from jose import JWTError, jwt

    from app.core.config import settings

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
async def request_password_reset(request: Request, reset_data: PasswordResetRequest):
    """비밀번호 재설정 요청"""
    # 실제 구현에서는 이메일 전송 로직 추가
    # 여기서는 요청을 받았다는 응답만 반환
    return {"message": "비밀번호 재설정 링크를 이메일로 전송했습니다."}


@router.post("/password-reset/confirm", status_code=status.HTTP_200_OK)
async def confirm_password_reset(
    request: Request,
    reset_data: PasswordResetConfirm,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """비밀번호 재설정 확인 및 변경"""
    # 토큰 검증 및 비밀번호 변경 로직 추가
    # 실제 구현에서는 토큰을 검증하고 비밀번호 변경 처리
    return {"message": "비밀번호가 성공적으로 변경되었습니다."}


@router.post("/password-change", status_code=status.HTTP_200_OK)
async def change_password(
    request: Request,
    password_data: ChangePasswordRequest,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """비밀번호 변경"""
    # 현재 비밀번호 검증 및 새 비밀번호로 변경하는 로직 추가
    # 실제 구현에서는 인증된 사용자의 비밀번호를 변경
    return {"message": "비밀번호가 성공적으로 변경되었습니다."}


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
