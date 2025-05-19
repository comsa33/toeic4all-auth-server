import redis

from ..core.config import settings
from ..utils.logger import logger


class RedisClient:
    client = None

    def connect_to_redis(self):
        """Redis 연결을 설정합니다."""
        logger.info("Redis 연결 중...")
        try:
            self.client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                password=settings.REDIS_PASSWORD,
                decode_responses=True,
            )
            ping = self.client.ping()
            if ping:
                logger.info("Redis 연결 성공")
                return self.client
            else:
                logger.error("Redis 응답 없음")
                raise Exception("Redis 서버가 응답하지 않습니다.")
        except Exception as e:
            logger.error(f"Redis 연결 실패: {e}")
            raise

    def get_client(self):
        """Redis 클라이언트를 반환합니다."""
        if not self.client:
            self.connect_to_redis()
        return self.client


# 싱글톤으로 사용할 인스턴스 생성
redis_client = RedisClient()
