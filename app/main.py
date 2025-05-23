import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, social
from app.core.config import settings
from app.db.mongodb import mongodb
from app.db.redis_client import redis_client
from app.utils.logger import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 시작 시 실행
    await mongodb.connect_to_mongo()
    redis_client.connect_to_redis()
    logger.info("Application startup complete")

    yield  # 애플리케이션 실행 중

    # 종료 시 실행
    await mongodb.close_mongo_connection()
    logger.info("Application shutdown complete")


app = FastAPI(
    title=settings.APP_NAME,
    description="TOEIC4ALL 인증 API",
    version="0.0.1",
    openapi_url=f"{settings.API_PREFIX}/openapi.json",
    docs_url=f"{settings.API_PREFIX}/docs",
    redoc_url=f"{settings.API_PREFIX}/redoc",
    lifespan=lifespan,  # 라이프스팬 이벤트 핸들러 등록
)

# CORS 미들웨어 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 라우터 등록
app.include_router(auth.router, prefix=f"{settings.API_PREFIX}", tags=["인증"])
app.include_router(
    social.router, prefix=f"{settings.API_PREFIX}/social", tags=["소셜 로그인"]
)


# 요청 처리 미들웨어 (로깅, 타이밍)
@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    start_time = time.time()

    # 요청 로깅
    logger.info(f"Request {request_id}: {request.method} {request.url.path}")

    try:
        response = await call_next(request)

        # 응답 로깅
        process_time = time.time() - start_time
        logger.info(
            f"Response {request_id}: {response.status_code} (took {process_time:.4f}s)"
        )

        return response
    except Exception as e:
        logger.error(f"Request {request_id} failed: {str(e)}")
        raise


# 상태 확인 엔드포인트
@app.get(f"{settings.API_PREFIX}/health", tags=["시스템"])
async def health_check():
    return {"status": "online", "api": "toeic4all-auth-server", "version": "0.1.0"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
