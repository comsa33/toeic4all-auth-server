import secrets
import smtplib
import string
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings
from app.db.mongodb import mongodb
from app.utils.logger import logger


def generate_verification_token(length: int = 64) -> str:
    """이메일 인증용 토큰 생성"""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def send_verification_email(email: str, username: str, token: str) -> bool:
    """이메일 인증 링크 발송"""
    try:
        verification_url = f"{settings.CLIENT_URL}/verify-email?token={token}"

        # 이메일 메시지 구성
        message = MIMEMultipart("alternative")
        message["Subject"] = "TOEIC4ALL 이메일 인증"
        message["From"] = settings.SMTP_SENDER
        message["To"] = email

        # HTML 버전 이메일 내용
        html = f"""
        <html>
        <body>
            <h2>안녕하세요, {username}님!</h2>
            <p>TOEIC4ALL에 가입해주셔서 감사합니다.</p>
            <p>아래 링크를 클릭하여 이메일 인증을 완료해주세요:</p>
            <p><a href="{verification_url}">이메일 인증하기</a></p>
            <p>링크가 작동하지 않을 경우 아래 URL을 브라우저에 복사하여 붙여넣기 해주세요:</p>
            <p>{verification_url}</p>
            <p>이 링크는 24시간 동안 유효합니다.</p>
            <p>감사합니다,<br>TOEIC4ALL 팀</p>
        </body>
        </html>
        """

        # 텍스트 버전 이메일 내용
        text = f"""
        안녕하세요, {username}님!
        
        TOEIC4ALL에 가입해주셔서 감사합니다.
        아래 링크를 클릭하여 이메일 인증을 완료해주세요:
        
        {verification_url}
        
        이 링크는 24시간 동안 유효합니다.
        
        감사합니다,
        TOEIC4ALL 팀
        """

        # 이메일에 내용 추가
        message.attach(MIMEText(text, "plain"))
        message.attach(MIMEText(html, "html"))

        # SMTP 서버에 연결하여 이메일 발송
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_SENDER, email, message.as_string())

        logger.info(f"이메일 인증 메일 발송 성공: {email}")
        return True

    except Exception as e:
        logger.error(f"이메일 발송 실패: {e}")
        return False


async def create_verification_token(user_id: str, email: str, username: str) -> bool:
    """이메일 인증 토큰 생성 및 저장"""
    token = generate_verification_token()
    users_collection = mongodb.get_users_db()

    # 토큰 저장 및 이메일 발송
    now = datetime.now()
    result = await users_collection.update_one(
        {"_id": user_id},
        {
            "$set": {
                "email_verification_token": token,
                "email_verification_sent_at": now,
            }
        },
    )

    if result.modified_count == 1:
        # 이메일 발송
        return await send_verification_email(email, username, token)

    return False


async def verify_email_token(token: str) -> bool:
    """이메일 인증 토큰 확인 및 인증 처리"""
    users_collection = mongodb.get_users_db()
    user = await users_collection.find_one({"email_verification_token": token})

    if not user:
        return False

    # 토큰 만료 확인 (24시간)
    sent_at = user.get("email_verification_sent_at")
    if not sent_at or (datetime.now() - sent_at) > timedelta(hours=24):
        return False

    # 인증 처리
    result = await users_collection.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"is_email_verified": True},
            "$unset": {
                "email_verification_token": "",
                "email_verification_sent_at": "",
            },
        },
    )

    return result.modified_count == 1
