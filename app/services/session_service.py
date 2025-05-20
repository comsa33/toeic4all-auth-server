import datetime
import json
import uuid
from typing import Dict, List, Optional

from jose import jwt

from app.core.config import settings
from app.db.redis_client import redis_client
from app.models.session import SessionModel
from app.utils.logger import logger


async def create_session(
    user_id: str,
    ip_address: str,
    device_info: Dict,
    refresh_token: str,
    access_token: Optional[str] = None,
) -> str:
    """새로운 세션 생성 및 Redis에 저장"""
    session_id = str(uuid.uuid4())
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    session = SessionModel(
        session_id=session_id,
        user_id=user_id,
        device_info=device_info,
        ip_address=ip_address,
        login_time=datetime.datetime.now(datetime.timezone.utc),
        expires_at=expires_at,
        refresh_token=refresh_token,
        access_token=access_token,
    )

    # Redis에 세션 정보 저장
    redis = redis_client.get_client()
    redis_key = f"session:{user_id}:{session_id}"

    # 세션 정보를 JSON으로 변환하여 저장

    session_data = json.dumps(session.model_dump(mode="json"))

    # 세션 TTL을 리프레시 토큰과 동일하게 설정
    ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    redis.setex(redis_key, ttl, session_data)

    # 사용자별 활성 세션 목록에 추가
    redis.sadd(f"user_sessions:{user_id}", session_id)

    return session_id


async def get_user_sessions(user_id: str) -> List[SessionModel]:
    """사용자의 모든 활성 세션 조회"""
    redis = redis_client.get_client()
    session_ids = redis.smembers(f"user_sessions:{user_id}")

    sessions = []
    for session_id in session_ids:
        session_data = redis.get(f"session:{user_id}:{session_id}")
        if session_data:

            session_dict = json.loads(session_data)
            # datetime 문자열을 datetime 객체로 변환
            for field in ["login_time", "expires_at"]:
                if field in session_dict:
                    session_dict[field] = datetime.datetime.fromisoformat(
                        session_dict[field]
                    )
            sessions.append(SessionModel(**session_dict))

    return sessions


async def terminate_session(user_id: str, session_id: str) -> bool:
    """특정 세션 종료"""

    redis = redis_client.get_client()
    session_key = f"session:{user_id}:{session_id}"
    session_data = redis.get(session_key)

    if not session_data:
        return False

    # 세션 데이터 파싱

    session_dict = json.loads(session_data)
    session = SessionModel(**session_dict)

    # 리프레시 토큰을 블랙리스트에 추가
    if session.refresh_token:
        try:
            # 토큰 만료 시간 확인
            payload = jwt.decode(
                session.refresh_token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM],
                options={"verify_exp": False},
            )
            exp = payload.get("exp", 0)
            current_time = datetime.datetime.now(datetime.timezone.utc).timestamp()
            ttl = max(0, int(exp - current_time))

            if ttl > 0:
                redis.setex(f"blacklist:{session.refresh_token}", ttl, "1")

        except Exception as e:
            logger.error(f"세션 종료 중 토큰 처리 오류: {e}")

    # 세션 정보 삭제
    redis.delete(session_key)
    redis.srem(f"user_sessions:{user_id}", session_id)

    return True


async def terminate_all_sessions_except_current(
    user_id: str, current_session_id: str
) -> int:
    """현재 세션을 제외한 모든 세션 종료"""
    redis = redis_client.get_client()
    session_ids = redis.smembers(f"user_sessions:{user_id}")

    terminated_count = 0
    for session_id in session_ids:
        if session_id != current_session_id:
            success = await terminate_session(user_id, session_id)
            if success:
                terminated_count += 1

    return terminated_count


async def clean_expired_sessions():
    """만료된 세션 정리 (백그라운드 작업용)"""
    redis = redis_client.get_client()
    all_users_pattern = "user_sessions:*"

    # 모든 사용자의 세션 키 가져오기
    user_keys = redis.keys(all_users_pattern)

    for user_key in user_keys:
        user_id = user_key.split(":")[-1]
        session_ids = redis.smembers(user_key)

        for session_id in session_ids:
            session_key = f"session:{user_id}:{session_id}"
            # 세션이 Redis에서 만료되었는지 확인
            if not redis.exists(session_key):
                redis.srem(user_key, session_id)
