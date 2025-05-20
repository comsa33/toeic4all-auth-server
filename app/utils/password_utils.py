import re
from typing import Tuple


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """비밀번호 강도 검증

    Returns:
        tuple: (유효성 여부, 에러 메시지)
    """
    if len(password) < 8:
        return False, "비밀번호는 최소 8자 이상이어야 합니다."

    if not re.search(r"[A-Z]", password):
        return False, "비밀번호는 최소 1개 이상의 대문자를 포함해야 합니다."

    if not re.search(r"[a-z]", password):
        return False, "비밀번호는 최소 1개 이상의 소문자를 포함해야 합니다."

    if not re.search(r"[0-9]", password):
        return False, "비밀번호는 최소 1개 이상의 숫자를 포함해야 합니다."

    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "비밀번호는 최소 1개 이상의 특수문자를 포함해야 합니다."

    return True, ""


def validate_username(username: str) -> Tuple[bool, str]:
    """사용자 이름 검증

    Returns:
        tuple: (유효성 여부, 에러 메시지)
    """
    if len(username) < 3:
        return False, "사용자 이름은 최소 3자 이상이어야 합니다."

    if not re.match(r"^[a-zA-Z0-9_-]+$", username):
        return False, "사용자 이름은 알파벳, 숫자, 밑줄, 하이픈만 포함할 수 있습니다."

    return True, ""
