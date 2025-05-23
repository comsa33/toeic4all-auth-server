import datetime
import secrets
import smtplib
import string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict

from bson.objectid import ObjectId

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
    now = datetime.datetime.now(datetime.timezone.utc)
    result = await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "email_verification_token": token,
                "email_verification_sent_at": now,
            }
        },
    )
    logger.info(f"{result} documents updated")
    logger.info(f"{result.modified_count} documents modified")

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
    if not sent_at or (
        datetime.datetime.now(datetime.timezone.utc) - sent_at
    ) > datetime.timedelta(hours=24):
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


async def send_security_alert(
    email: str,
    username: str,
    ip_address: str,
    device_info: Dict[str, Any],
    alert_type: str,
    alert_message: str,
) -> bool:
    """보안 알림 이메일 발송"""
    try:
        # 로그인 시간
        login_time = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # 이메일 메시지 구성
        message = MIMEMultipart("alternative")
        message["Subject"] = "TOEIC4ALL 계정 보안 알림"
        message["From"] = settings.SMTP_SENDER
        message["To"] = email

        # 디바이스 정보 포맷팅
        device_info_text = (
            f"기기 유형: {device_info.get('device_type', 'Unknown')}\n"
            f"운영체제: {device_info.get('os', 'Unknown')} {device_info.get('os_version', '')}\n"
            f"브라우저: {device_info.get('browser', 'Unknown')}\n"
            f"앱 버전: {device_info.get('app_version', 'Unknown')}"
        )

        device_info_html = (
            f"<p><strong>기기 유형:</strong> {device_info.get('device_type', 'Unknown')}<br>"
            f"<strong>운영체제:</strong> {device_info.get('os', 'Unknown')} {device_info.get('os_version', '')}<br>"
            f"<strong>브라우저:</strong> {device_info.get('browser', 'Unknown')}<br>"
            f"<strong>앱 버전:</strong> {device_info.get('app_version', 'Unknown')}</p>"
        )

        # HTML 버전 이메일 내용
        html = f"""
        <html>
        <body>
            <h2>안녕하세요, {username}님!</h2>
            <p><strong>{alert_type}</strong>에서 TOEIC4ALL 계정 로그인이 감지되었습니다.</p>
            <p>{alert_message}</p>
            
            <h3>로그인 세부 정보:</h3>
            <p><strong>시간:</strong> {login_time} (UTC)</p>
            <p><strong>IP 주소:</strong> {ip_address}</p>
            {device_info_html}
            
            <p>본인이 로그인한 것이 맞다면 이 메일을 무시하셔도 됩니다.</p>
            <p>본인이 아니라면, 즉시 <a href="{settings.CLIENT_URL}/password-reset">비밀번호를 변경</a>하고 
            <a href="{settings.CLIENT_URL}/account/sessions">활성 세션 관리</a>에서 모든 세션을 종료하세요.</p>
            
            <p>감사합니다,<br>TOEIC4ALL 팀</p>
        </body>
        </html>
        """

        # 텍스트 버전 이메일 내용
        text = f"""
        안녕하세요, {username}님!
        
        {alert_type}에서 TOEIC4ALL 계정 로그인이 감지되었습니다.
        {alert_message}
        
        로그인 세부 정보:
        시간: {login_time} (UTC)
        IP 주소: {ip_address}
        {device_info_text}
        
        본인이 로그인한 것이 맞다면 이 메일을 무시하셔도 됩니다.
        본인이 아니라면, 즉시 비밀번호를 변경하고 활성 세션을 모두 종료하세요:
        비밀번호 변경: {settings.CLIENT_URL}/password-reset
        세션 관리: {settings.CLIENT_URL}/account/sessions
        
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

        logger.info(f"보안 알림 이메일 발송 성공: {email}")
        return True

    except Exception as e:
        logger.error(f"보안 알림 이메일 발송 실패: {e}")
        return False


async def send_password_reset_email(email: str, username: str, token: str) -> bool:
    """비밀번호 재설정 링크 이메일 발송"""
    try:
        reset_url = f"{settings.CLIENT_URL}/password-reset-confirm?token={token}"

        # 이메일 메시지 구성
        message = MIMEMultipart("alternative")
        message["Subject"] = "TOEIC4ALL 비밀번호 재설정"
        message["From"] = settings.SMTP_SENDER
        message["To"] = email

        # HTML 버전 이메일 내용
        html = f"""
        <html>
        <body>
            <h2>안녕하세요, {username}님!</h2>
            <p>TOEIC4ALL 계정의 비밀번호 재설정을 요청하셨습니다.</p>
            <p>아래 링크를 클릭하여 비밀번호를 재설정해주세요:</p>
            <p><a href="{reset_url}">비밀번호 재설정하기</a></p>
            <p>링크가 작동하지 않을 경우 아래 URL을 브라우저에 복사하여 붙여넣기 해주세요:</p>
            <p>{reset_url}</p>
            <p>이 링크는 24시간 동안 유효합니다.</p>
            <p>만약 비밀번호 재설정을 요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.</p>
            <p>감사합니다,<br>TOEIC4ALL 팀</p>
        </body>
        </html>
        """

        # 텍스트 버전 이메일 내용
        text = f"""
        안녕하세요, {username}님!
        
        TOEIC4ALL 계정의 비밀번호 재설정을 요청하셨습니다.
        아래 링크를 클릭하여 비밀번호를 재설정해주세요:
        
        {reset_url}
        
        이 링크는 24시간 동안 유효합니다.
        
        만약 비밀번호 재설정을 요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.
        
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

        logger.info(f"비밀번호 재설정 이메일 발송 성공: {email}")
        return True

    except Exception as e:
        logger.error(f"비밀번호 재설정 이메일 발송 실패: {e}")
        return False
