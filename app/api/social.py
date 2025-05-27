import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from google.auth.transport import requests
from google.oauth2 import id_token

from app.api.dependencies import get_user_ip_and_device_info
from app.core.config import settings
from app.schemas.auth import (
    GoogleMobileLoginRequest,
    KakaoMobileLoginRequest,
    LoginResponse,
    NaverMobileLoginRequest,
)
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
    """모바일 앱용 구글 로그인 (ID 토큰 방식) - 플랫폼별 클라이언트 ID 지원"""
    try:
        # ID Token 형식 검증
        if not auth_data.id_token or len(auth_data.id_token.split(".")) != 3:
            logger.error(f"잘못된 ID Token 형식: {auth_data.id_token[:100]}...")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="올바른 Google ID Token 형식이 아닙니다. JWT 토큰이어야 합니다.",
            )

        logger.info(f"ID Token 검증 시작: {auth_data.id_token[:50]}...")

        # 🔄 여러 클라이언트 ID로 순차 검증
        client_ids = settings.GOOGLE_CLIENT_IDS
        if not client_ids:
            logger.error("Google 클라이언트 ID가 설정되지 않았습니다.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Google 로그인 설정 오류입니다.",
            )

        logger.info(f"검증할 클라이언트 ID 목록: {len(client_ids)}개")

        idinfo = None
        verified_client_id = None

        # 각 클라이언트 ID로 순차 검증 시도
        for client_id in client_ids:
            try:
                logger.info(f"클라이언트 ID 검증 시도: {client_id[-10:]}...")

                idinfo = id_token.verify_oauth2_token(
                    auth_data.id_token, requests.Request(), client_id
                )

                verified_client_id = client_id
                logger.info(
                    f"ID Token 검증 성공: {client_id[-10:]}... for {idinfo.get('email')}"
                )
                break

            except ValueError as ve:
                logger.warning(f"클라이언트 ID {client_id[-10:]}... 검증 실패: {ve}")
                continue

        # 모든 클라이언트 ID 검증 실패
        if idinfo is None:
            logger.error("모든 클라이언트 ID에서 검증 실패")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="유효하지 않은 Google ID 토큰입니다.",
            )

        # 발급자 확인
        if idinfo["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            logger.error(f"잘못된 발급자: {idinfo['iss']}")
            raise ValueError("Invalid issuer.")

        # 사용자 정보 추출
        user_id = idinfo["sub"]
        email = idinfo["email"]
        name = idinfo.get("name", "")
        picture = idinfo.get("picture", "")

        logger.info(
            f"사용자 정보 추출 완료: {email} (클라이언트: {verified_client_id[-10:]}...)"
        )

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

        logger.info(f"로그인 처리 완료: {user.username}")

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


@router.post("/kakao/mobile", response_model=LoginResponse)
async def kakao_mobile_login(
    request: Request,
    auth_data: KakaoMobileLoginRequest,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """모바일 앱용 카카오 로그인 (Access Token 방식)"""
    try:
        logger.info(f"카카오 모바일 로그인 시작: {auth_data.access_token[:20]}...")

        # 카카오 사용자 정보 조회
        async with httpx.AsyncClient() as client:
            userinfo_url = "https://kapi.kakao.com/v2/user/me"
            headers = {"Authorization": f"Bearer {auth_data.access_token}"}

            userinfo_response = await client.get(userinfo_url, headers=headers)

            if userinfo_response.status_code != 200:
                logger.error(f"카카오 사용자 정보 조회 실패: {userinfo_response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="유효하지 않은 카카오 액세스 토큰입니다.",
                )

            user_info = userinfo_response.json()
            logger.info(f"카카오 사용자 정보 조회 성공: {user_info.get('id')}")

        # 사용자 정보 추출
        kakao_account = user_info.get("kakao_account", {})
        profile = kakao_account.get("profile", {})

        user_id = str(user_info["id"])
        email = kakao_account.get("email", f"{user_id}@kakao.user")
        name = profile.get("nickname", "")
        profile_image = profile.get("profile_image_url", "")

        ip_address, device_info = ip_and_device

        # 기존 소셜 로그인 로직 재사용
        user, access_token, refresh_token = await process_social_login(
            provider="kakao",
            provider_user_id=user_id,
            email=email,
            username=f"kakao_{user_id}",
            name=name,
            profile_image=profile_image,
            ip_address=ip_address,
            device_info=device_info,
        )

        logger.info(f"카카오 모바일 로그인 완료: {user.username}")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user_id": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"카카오 모바일 로그인 오류: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="카카오 로그인 처리 중 오류가 발생했습니다.",
        )


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


@router.post("/naver/mobile", response_model=LoginResponse)
async def naver_mobile_login(
    request: Request,
    auth_data: NaverMobileLoginRequest,
    ip_and_device: tuple = Depends(get_user_ip_and_device_info),
):
    """모바일 앱용 네이버 로그인 (Access Token 방식)"""
    try:
        logger.info(f"네이버 모바일 로그인 시작: {auth_data.access_token[:20]}...")

        # 네이버 사용자 정보 조회
        async with httpx.AsyncClient() as client:
            userinfo_url = "https://openapi.naver.com/v1/nid/me"
            headers = {"Authorization": f"Bearer {auth_data.access_token}"}

            userinfo_response = await client.get(userinfo_url, headers=headers)

            if userinfo_response.status_code != 200:
                logger.error(f"네이버 사용자 정보 조회 실패: {userinfo_response.text}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="유효하지 않은 네이버 액세스 토큰입니다.",
                )

            user_info = userinfo_response.json()
            logger.info(
                f"네이버 사용자 정보 조회 성공: {user_info.get('response', {}).get('id')}"
            )

        # 사용자 정보 추출
        response = user_info.get("response", {})

        user_id = response.get("id", "")
        email = response.get("email", f"{user_id}@naver.user")
        name = response.get("name", "")
        profile_image = response.get("profile_image", "")
        nickname = response.get("nickname", "")

        # 이름이 없으면 닉네임 사용
        display_name = name if name else nickname

        ip_address, device_info = ip_and_device

        # 기존 소셜 로그인 로직 재사용
        user, access_token, refresh_token = await process_social_login(
            provider="naver",
            provider_user_id=user_id,
            email=email,
            username=f"naver_{user_id}",
            name=display_name,
            profile_image=profile_image,
            ip_address=ip_address,
            device_info=device_info,
        )

        logger.info(f"네이버 모바일 로그인 완료: {user.username}")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user_id": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"네이버 모바일 로그인 오류: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="네이버 로그인 처리 중 오류가 발생했습니다.",
        )
