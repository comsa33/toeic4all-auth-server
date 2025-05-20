import datetime
import logging
import os
import sys
from pathlib import Path

from app.core.config import settings


def setup_logger():
    """애플리케이션 로깅 설정"""
    # 로그 레벨 설정
    log_level_str = settings.LOG_LEVEL.upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # 로거 생성
    logger = logging.getLogger("toeic4all-auth")
    logger.setLevel(log_level)
    logger.propagate = False

    # 이미 핸들러가 설정되어 있으면 중복 설정 방지
    if logger.handlers:
        return logger

    # 콘솔 핸들러 설정
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # 로그 포맷 설정
    log_format = "[%(asctime)s] [%(levelname)s] [%(name)s] - %(message)s"
    formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
    console_handler.setFormatter(formatter)

    # 로거에 핸들러 추가
    logger.addHandler(console_handler)

    # 파일 로깅 설정 (선택적)
    log_to_file = os.getenv("LOG_TO_FILE", "false").lower() == "true"

    if log_to_file:
        # 로그 디렉토리 생성
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        # 날짜별 로그 파일
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        log_file = log_dir / f"toeic4all-auth-{today}.log"

        # 파일 핸들러 설정
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)

        # 로거에 파일 핸들러 추가
        logger.addHandler(file_handler)

    # 로그 시작 메시지
    logger.info("Logger initialized with level: %s", log_level_str)
    return logger


# 전역 로거 인스턴스 생성
logger = setup_logger()
