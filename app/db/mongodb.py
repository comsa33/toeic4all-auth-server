from typing import Any, Dict

from pymongo import AsyncMongoClient
from pymongo.database import Database

from ..core.config import settings
from ..utils.logger import logger


class MongoDB:
    client: AsyncMongoClient = None

    async def connect_to_mongo(self):
        """MongoDB 연결을 설정합니다."""
        logger.info("MongoDB 연결 중...")
        try:
            # 비동기 MongoDB 클라이언트 생성
            self.client = AsyncMongoClient(
                settings.MONGODB_URI,
                tz_aware=True,  # datetime 객체를 타임존 인식으로 처리
                connect=False,  # 첫 작업 시 연결 (FastAPI 비동기 환경에 권장)
            )
            # 연결 확인 - 비동기 핑
            await self.client.admin.command("ping")
            logger.info("MongoDB 연결 성공")
        except Exception as e:
            logger.error(f"MongoDB 연결 실패: {e}")
            raise

    async def close_mongo_connection(self):
        """MongoDB 연결을 종료합니다."""
        logger.info("MongoDB 연결 종료 중...")
        if self.client:
            await self.client.close()  # 비동기 close 메서드 사용
            logger.info("MongoDB 연결 종료됨")

    def get_users_db(self) -> Database:
        """사용자 컬렉션에 대한 액세스를 제공합니다."""
        return self.client[settings.MONGODB_NAME].users

    def get_auth_logs_db(self) -> Database:
        """인증 로그 컬렉션에 대한 액세스를 제공합니다."""
        return self.client[settings.MONGODB_NAME].auth_logs

    async def get_server_stats(self) -> Dict[str, Any]:
        """MongoDB 서버 상태 정보를 가져옵니다."""
        return await self.client.admin.command("serverStatus")


# 싱글톤으로 사용할 인스턴스 생성
mongodb = MongoDB()
