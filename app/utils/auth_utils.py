from typing import Any, Dict

from app.schemas.auth import LoginProvider


def determine_login_provider(user: Dict[str, Any]) -> str:
    """
    사용자 정보를 기반으로 login_provider를 결정합니다.

    Args:
        user: 사용자 정보 딕셔너리

    Returns:
        str: LoginProvider enum 값 중 하나
    """
    social_connections = user.get("social_connections", {})

    # 소셜 연결이 없으면 일반 로그인
    if not social_connections:
        return LoginProvider.USERNAME.value

    # 소셜 연결이 있는 경우, 최근 로그인한 제공자를 확인
    # 각 소셜 연결의 last_login 시간을 비교하여 가장 최근 것을 선택
    latest_provider = None
    latest_login = None

    for provider, connection_info in social_connections.items():
        if isinstance(connection_info, dict) and connection_info.get("last_login"):
            if latest_login is None or connection_info["last_login"] > latest_login:
                latest_login = connection_info["last_login"]
                latest_provider = provider

    # 최근 로그인 제공자가 있으면 해당 제공자 반환
    if latest_provider:
        if latest_provider == "google":
            return LoginProvider.GOOGLE.value
        elif latest_provider == "kakao":
            return LoginProvider.KAKAO.value
        elif latest_provider == "naver":
            return LoginProvider.NAVER.value

    # 소셜 연결은 있지만 last_login 정보가 없는 경우, 우선순위에 따라 결정
    if "google" in social_connections:
        return LoginProvider.GOOGLE.value
    elif "kakao" in social_connections:
        return LoginProvider.KAKAO.value
    elif "naver" in social_connections:
        return LoginProvider.NAVER.value

    # 기본값은 일반 로그인
    return LoginProvider.USERNAME.value


def get_login_provider_from_social_login(provider: str) -> str:
    """
    소셜 로그인 제공자 문자열을 LoginProvider enum 값으로 변환합니다.

    Args:
        provider: 소셜 로그인 제공자 ("google", "kakao", "naver")

    Returns:
        str: LoginProvider enum 값
    """
    provider_mapping = {
        "google": LoginProvider.GOOGLE.value,
        "kakao": LoginProvider.KAKAO.value,
        "naver": LoginProvider.NAVER.value,
    }

    return provider_mapping.get(provider, LoginProvider.USERNAME.value)
