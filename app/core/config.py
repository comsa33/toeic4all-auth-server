import json
from typing import Any, List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"  # 환경 설정 (development, production)

    # 애플리케이션 설정
    APP_NAME: str = "TOEIC4ALL Auth API"
    API_PREFIX: str = "/api/v1"

    # Read BACKEND_CORS_ORIGINS from .env as a raw string
    # The alias ensures it still reads the 'BACKEND_CORS_ORIGINS' env variable
    BACKEND_CORS_ORIGINS_RAW: str = Field(default="*", alias="BACKEND_CORS_ORIGINS")

    # MongoDB 설정
    MONGODB_URI: str
    MONGODB_NAME: str = "toeic4all_users"

    # Redis 설정 (토큰 저장 및 블랙리스트 관리)
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    # JWT 설정
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # 소셜 로그인 설정
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None

    GOOGLE_CLIENT_ID_IOS: Optional[str] = None
    GOOGLE_CLIENT_ID_ANDROID: Optional[str] = None

    KAKAO_CLIENT_ID: Optional[str] = None

    NAVER_CLIENT_ID: Optional[str] = None
    NAVER_CLIENT_SECRET: Optional[str] = None

    # 이메일 설정
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_SENDER: str = "noreply@toeic4all.com"
    SMTP_USE_TLS: bool = True

    # 클라이언트 URL (이메일 인증 링크용)
    CLIENT_URL: str = "https://toeic4all.po24lio.com"

    # 로깅 설정
    LOG_LEVEL: str = "INFO"

    @property
    def GOOGLE_CLIENT_IDS(self) -> List[str]:
        """모든 Google 클라이언트 ID 목록 반환"""
        client_ids = []

        # 플랫폼별 클라이언트 ID 추가
        if self.GOOGLE_CLIENT_ID_IOS:
            client_ids.append(self.GOOGLE_CLIENT_ID_IOS)
        if self.GOOGLE_CLIENT_ID_ANDROID:
            client_ids.append(self.GOOGLE_CLIENT_ID_ANDROID)

        # 기존 클라이언트 ID도 포함 (하위 호환성)
        if self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_ID not in client_ids:
            client_ids.append(self.GOOGLE_CLIENT_ID)

        return client_ids

    # boolean 필드에 대한 유효성 검사 추가
    @field_validator("SMTP_USE_TLS")
    @classmethod
    def parse_bool(cls, v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            # 빈 문자열이나 null 문자열은 기본값 True 사용
            if v.lower() in ("", "null", "none"):
                return True
            # 명시적으로 true/false 문자열 처리
            if v.lower() in ("true", "t", "yes", "y", "1"):
                return True
            if v.lower() in ("false", "f", "no", "n", "0"):
                return False
        # 다른 모든 경우 기본값 True 사용
        return True

    # Define BACKEND_CORS_ORIGINS as a property that parses the raw string
    @property
    def BACKEND_CORS_ORIGINS(self) -> List[str]:
        v = self.BACKEND_CORS_ORIGINS_RAW

        # Check if the string is intended to be a JSON array
        if v.startswith("[") and v.endswith("]"):
            try:
                data = json.loads(v)  # Attempt to parse as JSON
                if isinstance(data, list) and all(isinstance(s, str) for s in data):
                    return data  # Successfully parsed as list of strings
                else:
                    # Parsed as JSON, but not a list of strings (e.g., list of ints, or a dict)
                    raise ValueError(
                        f"BACKEND_CORS_ORIGINS env var '{v}' looks like JSON array but is not a list of strings."
                    )
            except json.JSONDecodeError as e:
                # Starts and ends with [], but not valid JSON (e.g. "['foo']" or "[foo,bar]")
                raise ValueError(
                    f"BACKEND_CORS_ORIGINS env var '{v}' looks like JSON array but is malformed: {e}"
                )
        else:
            # Not a JSON array string, treat as comma-separated.
            # Handles "*", "foo", "foo,bar"
            # This will return [''] for an empty string v="", and ['foo'] for v="foo"
            return [item.strip() for item in v.split(",")]

    # Use model_config for Pydantic v2 settings
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)


settings = Settings()
