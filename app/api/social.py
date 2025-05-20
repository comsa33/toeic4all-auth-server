from fastapi import APIRouter, Depends, Query, Request

from app.api.dependencies import get_user_ip_and_device_info
from app.schemas.auth import LoginResponse
from app.services.social_service import (
    handle_google_login,
    handle_kakao_login,
    handle_naver_login,
)

router = APIRouter()


@router.post("/google", response_model=LoginResponse)
async def google_login(
    request: Request,
    code: str = Query(..., description="Google에서 반환된 인증 코드"),
    redirect_uri: str = Query(..., description="리디렉션 URI"),
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """Google 소셜 로그인"""
    ip_address, device_info = ip_and_device
    user, access_token, refresh_token = await handle_google_login(
        code=code,
        redirect_uri=redirect_uri,
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


@router.post("/kakao", response_model=LoginResponse)
async def kakao_login(
    request: Request,
    code: str = Query(..., description="Kakao에서 반환된 인증 코드"),
    redirect_uri: str = Query(..., description="리디렉션 URI"),
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """Kakao 소셜 로그인"""
    ip_address, device_info = ip_and_device
    user, access_token, refresh_token = await handle_kakao_login(
        code=code,
        redirect_uri=redirect_uri,
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


@router.post("/naver", response_model=LoginResponse)
async def naver_login(
    request: Request,
    code: str = Query(..., description="Naver에서 반환된 인증 코드"),
    redirect_uri: str = Query(..., description="리디렉션 URI"),
    state: str = Query(..., description="상태 문자열"),  # state 매개변수 추가
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """Naver 소셜 로그인"""
    ip_address, device_info = ip_and_device
    user, access_token, refresh_token = await handle_naver_login(
        code=code,
        redirect_uri=redirect_uri,
        state=state,  # state 파라미터 전달
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
