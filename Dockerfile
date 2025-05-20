FROM ubuntu:22.04

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1 \
    PIP_NO_CACHE_DIR=on \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    # 로깅 설정
    LOG_LEVEL="INFO"

# 시스템 패키지 설치
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# uv 도구 복사
COPY --from=ghcr.io/astral-sh/uv:0.6.14 /uv /uvx /bin/

# 이미지 레이어 최적화 - 자주 변경되지 않는 종속성과 파일부터 복사
WORKDIR /app

# 종속성 설치 (캐싱 활용)
COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-cache

COPY . .

# 애플리케이션 포트 노출
EXPOSE 8000

# 건강 체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# 애플리케이션 실행
CMD ["uv", "run", "-m", "app.main:app"]