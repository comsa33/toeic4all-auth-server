import datetime
import secrets
import string
from typing import Any, Dict, Tuple
from urllib.parse import unquote

import httpx
from fastapi import HTTPException, status

from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token
from app.db.mongodb import mongodb
from app.models.user import UserModel
from app.utils.logger import logger


def generate_random_password(length: int = 16) -> str:
    """랜덤 비밀번호 생성"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def handle_google_login(
    code: str, redirect_uri: str, ip_address: str, device_info: Dict[str, Any]
) -> Tuple[UserModel, str, str]:
    """Google OAuth 로그인 처리"""
    # 액세스 토큰 획득
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "code": unquote(code),
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient() as client:
        token_response = await client.post(token_url, data=token_data)
        if token_response.status_code != 200:
            logger.error(f"Google 토큰 요청 실패: {token_response.text}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google 인증에 실패했습니다.",
            )

        token_data = token_response.json()
        id_token = token_data.get("id_token")

        # 사용자 정보 획득
        userinfo_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
        userinfo_response = await client.get(userinfo_url)

        if userinfo_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google 사용자 정보를 가져오는데 실패했습니다.",
            )

        user_info = userinfo_response.json()

    return await process_social_login(
        provider="google",
        provider_user_id=user_info["sub"],
        email=user_info["email"],
        username=user_info.get("email", "").split("@")[
            0
        ],  # 이메일의 @ 앞부분을 기본 사용자 이름으로 사용
        name=user_info.get("name", ""),
        profile_image=user_info.get("picture", ""),
        ip_address=ip_address,
        device_info=device_info,
    )


async def handle_kakao_login(
    code: str, redirect_uri: str, ip_address: str, device_info: Dict[str, Any]
) -> Tuple[UserModel, str, str]:
    """Kakao OAuth 로그인 처리"""
    # 액세스 토큰 획득
    token_url = "https://kauth.kakao.com/oauth/token"
    token_data = {
        "grant_type": "authorization_code",
        "client_id": settings.KAKAO_CLIENT_ID,
        "code": unquote(code),
        "redirect_uri": redirect_uri,
    }

    async with httpx.AsyncClient() as client:
        token_response = await client.post(token_url, data=token_data)
        if token_response.status_code != 200:
            logger.error(f"Kakao 토큰 요청 실패: {token_response.text}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kakao 인증에 실패했습니다.",
            )

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        # 사용자 정보 획득
        userinfo_url = "https://kapi.kakao.com/v2/user/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        userinfo_response = await client.get(userinfo_url, headers=headers)

        if userinfo_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Kakao 사용자 정보를 가져오는데 실패했습니다.",
            )

        user_info = userinfo_response.json()

    return await process_social_login(
        provider="kakao",
        provider_user_id=str(user_info["id"]),
        email=user_info.get("kakao_account", {}).get(
            "email", f"{user_info['id']}@kakao.user"
        ),
        username=f"kakao_{user_info['id']}",
        name=user_info.get("kakao_account", {}).get("profile", {}).get("nickname", ""),
        profile_image=user_info.get("kakao_account", {})
        .get("profile", {})
        .get("profile_image_url", ""),
        ip_address=ip_address,
        device_info=device_info,
    )


async def handle_naver_login(
    code: str,
    redirect_uri: str,
    state: str,
    ip_address: str,
    device_info: Dict[str, Any],
) -> Tuple[UserModel, str, str]:
    """Naver OAuth 로그인 처리"""
    # 액세스 토큰 획득
    token_url = "https://nid.naver.com/oauth2.0/token"
    token_data = {
        "grant_type": "authorization_code",
        "client_id": settings.NAVER_CLIENT_ID,
        "client_secret": settings.NAVER_CLIENT_SECRET,
        "code": code,
        "redirect_uri": redirect_uri,
        "state": state,  # state 매개변수 추가
    }

    async with httpx.AsyncClient() as client:
        token_response = await client.post(token_url, data=token_data)
        if token_response.status_code != 200:
            logger.error(f"Naver 토큰 요청 실패: {token_response.text}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Naver 인증에 실패했습니다.",
            )

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        # 사용자 정보 획득
        userinfo_url = "https://openapi.naver.com/v1/nid/me"
        headers = {"Authorization": f"Bearer {access_token}"}
        userinfo_response = await client.get(userinfo_url, headers=headers)

        if userinfo_response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Naver 사용자 정보를 가져오는데 실패했습니다.",
            )

        user_info = userinfo_response.json()
        response = user_info.get("response", {})

    return await process_social_login(
        provider="naver",
        provider_user_id=response.get("id", ""),
        email=response.get("email", f"{response.get('id', '')}@naver.user"),
        username=f"naver_{response.get('id', '')}",
        name=response.get("name", ""),
        profile_image=response.get("profile_image", ""),
        ip_address=ip_address,
        device_info=device_info,
    )


async def process_social_login(
    provider: str,
    provider_user_id: str,
    email: str,
    username: str,
    name: str,
    profile_image: str,
    ip_address: str,
    device_info: Dict[str, Any],
) -> Tuple[UserModel, str, str]:
    """소셜 로그인 공통 처리 로직"""
    from app.services.auth_service import log_auth_event

    users_collection = mongodb.get_users_db()

    # 1. 소셜 연결을 통한 사용자 조회
    user = await users_collection.find_one(
        {f"social_connections.{provider}.id": provider_user_id}
    )

    # 2. 이메일을 통한 사용자 조회
    if not user:
        user = await users_collection.find_one({"email": email})

    # 3. 사용자가 존재하면 소셜 정보 업데이트 후 로그인
    if user:
        # 소셜 연결 정보 업데이트
        await users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    f"social_connections.{provider}": {
                        "id": provider_user_id,
                        "last_login": datetime.datetime.now(datetime.timezone.utc),
                    },
                    "last_login": datetime.datetime.now(datetime.timezone.utc),
                }
            },
        )
    else:
        # 4. 사용자가 없으면 새 계정 생성
        # 사용자 이름 중복 방지
        base_username = username
        num = 1

        while await users_collection.find_one({"username": username}):
            username = f"{base_username}_{num}"
            num += 1

        # 랜덤 비밀번호 생성 (소셜 로그인만 사용할 경우 필요 없지만, 필요시를 대비)
        random_password = generate_random_password()

        from app.core.security import get_password_hash

        new_user = {
            "username": username,
            "email": email,
            "password_hash": get_password_hash(random_password),
            "profile": {
                "full_name": name,
                "profile_image": profile_image,
                "bio": "",  # None 대신 빈 문자열 사용
                "preferences": {
                    "notification_enabled": True,
                    "theme": "light",
                    "language": "ko",
                },
            },
            "stats": {
                "part5_correct": 0,
                "part5_total": 0,
                "part6_correct": 0,
                "part6_total": 0,
                "part7_correct": 0,
                "part7_total": 0,
                "last_activity": datetime.datetime.now(
                    datetime.timezone.utc
                ),  # None 대신 현재 시간 사용
                "streak_days": 0,
            },
            "subscription": {
                "plan": "free",
                "start_date": datetime.datetime.now(datetime.timezone.utc),
                "end_date": datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=30),  # None 대신 30일 후 날짜 사용
                "is_active": True,
                "payment_id": "",  # None 대신 빈 문자열 사용
            },
            "created_at": datetime.datetime.now(datetime.timezone.utc),
            "updated_at": datetime.datetime.now(
                datetime.timezone.utc
            ),  # None 대신 현재 시간 사용
            "last_login": datetime.datetime.now(datetime.timezone.utc),
            "refresh_token": "",  # None 대신 빈 문자열 사용
            "is_active": True,
            "role": "user",
            "social_connections": {
                provider: {
                    "id": provider_user_id,
                    "last_login": datetime.datetime.now(datetime.timezone.utc),
                }
            },
        }

        result = await users_collection.insert_one(new_user)
        user = await users_collection.find_one({"_id": result.inserted_id})

        # 회원가입 이벤트 기록
        await log_auth_event(
            user_id=str(user["_id"]),
            username=user["username"],
            event_type="signup",
            ip_address=ip_address,
            device_info=device_info,
            status="success",
            details={"provider": provider},
        )

    # 토큰 생성
    access_token = create_access_token(
        subject=str(user["_id"]), role=user.get("role", "user")
    )
    refresh_token = create_refresh_token(
        subject=str(user["_id"]), role=user.get("role", "user")
    )

    # 리프레시 토큰 저장
    await users_collection.update_one(
        {"_id": user["_id"]}, {"$set": {"refresh_token": refresh_token}}
    )

    # 로그인 이벤트 기록
    await log_auth_event(
        user_id=str(user["_id"]),
        username=user["username"],
        event_type="login_success",
        ip_address=ip_address,
        device_info=device_info,
        status="success",
        details={"provider": provider},
    )

    return UserModel(**user), access_token, refresh_token
