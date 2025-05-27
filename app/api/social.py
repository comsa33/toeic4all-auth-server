from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from google.auth.transport import requests
from google.oauth2 import id_token

from app.api.dependencies import get_user_ip_and_device_info
from app.core.config import settings
from app.schemas.auth import GoogleMobileLoginRequest, LoginResponse
from app.services.social_service import (
    handle_google_login,
    handle_kakao_login,
    handle_naver_login,
    process_social_login,
)
from app.utils.logger import logger

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


@router.post("/google/mobile", response_model=LoginResponse)
async def google_mobile_login(
    request: Request,
    auth_data: GoogleMobileLoginRequest,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """모바일 앱용 구글 로그인 (ID 토큰 방식)"""
    try:
        # ID 토큰 검증
        idinfo = id_token.verify_oauth2_token(
            auth_data.id_token, requests.Request(), settings.GOOGLE_CLIENT_ID
        )

        # 발급자 확인
        if idinfo["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError("Invalid issuer.")

        # 사용자 정보 추출
        user_id = idinfo["sub"]
        email = idinfo["email"]
        name = idinfo.get("name", "")
        picture = idinfo.get("picture", "")

        ip_address, device_info = ip_and_device

        # 기존 소셜 로그인 로직 재사용
        user, access_token, refresh_token = await process_social_login(
            provider="google",
            provider_user_id=user_id,
            email=email,
            username=email.split("@")[0],
            name=name,
            profile_image=picture,
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

    except ValueError as ve:
        logger.error(f"ID 토큰 검증 실패: {ve}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 Google ID 토큰입니다.",
        )
    except Exception as e:
        logger.error(f"Google 모바일 로그인 오류: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google 로그인 처리 중 오류가 발생했습니다.",
        )


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
