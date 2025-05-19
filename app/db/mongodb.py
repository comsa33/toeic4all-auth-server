from motor.motor_asyncio import AsyncIOMotorClient

from ..core.config import settings
from ..utils.logger import logger


class MongoDB:
    client: AsyncIOMotorClient = None

    async def connect_to_mongo(self):
        """MongoDB 연결을 설정합니다."""
        logger.info("MongoDB 연결 중...")
        try:
            self.client = AsyncIOMotorClient(settings.MONGODB_URL)
            logger.info("MongoDB 연결 성공")
        except Exception as e:
            logger.error(f"MongoDB 연결 실패: {e}")
            raise

    async def close_mongo_connection(self):
        """MongoDB 연결을 종료합니다."""
        logger.info("MongoDB 연결 종료 중...")
        if self.client:
            self.client.close()
            logger.info("MongoDB 연결 종료됨")

    def get_users_db(self):
        """사용자 컬렉션에 대한 액세스를 제공합니다."""
        return self.client[settings.MONGODB_NAME].users

    def get_auth_logs_db(self):
        """인증 로그 컬렉션에 대한 액세스를 제공합니다."""
        return self.client[settings.MONGODB_NAME].auth_logs


# 싱글톤으로 사용할 인스턴스 생성
mongodb = MongoDB()
