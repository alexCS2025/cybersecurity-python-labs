import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

PBKDF_ITERATIONS = 600_000
SESSION_TIMEOUT = 900


class User:
    def __init__(self, username: str, email: str, role: str):
        self.username = username
        self._email = email
        self.role = role
        self.active = True
        self.__password_hash: str
        self.__password_salt: str

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, email: str):
        if re.search(r"[^a-zA-Z0-9._@]", email):
            raise ValueError(
                "Email cannot contain any characters except for latin characters, digits, '@', '_', '.'"
            )

        local_part, domain = email.split("@")

        first_is_latin = bool(re.match(r"[a-zA-Z]", local_part))
        if not first_is_latin:
            raise ValueError("First symbol of your email must be a latin character")

        latin_count = bool(64 >= len(re.findall(r"[a-zA-Z]", local_part)) >= 3)
        if not latin_count:
            raise ValueError(
                "Your email must contain less than 64 and at least 3 latin characters"
            )

        dot_count = bool(re.findall(r"[.]", domain))
        if not dot_count:
            raise ValueError("Email domain needs to contain a dot")

    # Якщо я маю один пароль перше і сіль до нього потім я міняю пароль; сіль має мінятися?
    # Має мінятися при зміні пароля
    def set_password(self, password: str):
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, PBKDF_ITERATIONS, 32
        )

    def check_password(self, password: str) -> bool:
        # Використовувати hmac.compare_digest, бо він захищений від атак за часом
        hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, PBKDF_ITERATIONS, 32
        )
        return hmac.compare_digest(hash, self.__password_hash)

    def deactivate(self):
        self.active = False

    def __str__(self):
        return f"User: {self.username}\nEmail: {self.email}\nRole: {self.role}\nActive: {self.active}"


class Admin(User):
    def __init__(self, username, email, role):
        super().__init__(username, email, role)
        self.permissions = set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)

    def revoke_permission(self, permission: str):
        try:
            self.permissions.remove(permission)
        except KeyError:
            print("Can't revoke a permission that is not granted to this user")

    def has_permission(self, permission: str) -> bool:
        if permission in self.permissions:
            return True
        return False

    def __str__(self):
        return (
            super().__str__()
            + f"\nPermissions: {self.permissions if self.permissions else 'None'}"
        )


class Session:
    def __init__(self, ip: str, login_time: datetime, last_activity: datetime):
        self.ip = ip
        self.login_time = login_time
        self.last_activity = last_activity

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        # може raise ValueError?
        if timeout_sec < 0:
            print("Timeout value can't be negative")
            return

        time_now = datetime.now(timezone.utc)
        delta = time_now - self.last_activity

        if delta.total_seconds() >= timeout_sec:
            return False
        return True


# freeze щоб не зробити незмінним
@dataclass(frozen=True)
class AuditLogEntry:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.records = []

    def add_log(self, username: str, action: str):
        self.records.append(AuditLogEntry(datetime.now(timezone.utc), username, action))

    def show_all(self):
        for record in self.records:
            print(
                f"[{record.timestamp.isoformat()}] {record.username}: {record.action}"
            )


class UserAccount:
    def __init__(self, user: User, audit_log: AuditLog = None):
        self.user = user
        self.session = None
        self.audit_log = audit_log

    def login(self, password: str, ip: str):
        if not self.user.active:
            self.audit_log.add_log(self.user.username, "login_fail_inactive")
            return False

        if self.user.check_password(password):
            self.session = Session(
                ip, datetime.now(timezone.utc), datetime.now(timezone.utc)
            )
            self.audit_log.add_log(self.user.username, "login_success")
            return True
        else:
            self.audit_log.add_log(self.user.username, "login_fail_wrongpass")
            return False

    def is_authenticated(self) -> bool:
        if self.session and self.session.is_active(SESSION_TIMEOUT):
            self.session.touch()
            return True
        return False

    def logout(self):
        if self.session:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit_log":
            return self.audit_log
        else:
            raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key, value):
        if key == "user" and isinstance(value, User):
            self.user = value
        elif key == "session" and (isinstance(value, Session) or value is None):
            self.session = value
        elif key == "audit_log" and isinstance(value, AuditLog):
            self.audit_log = value
        else:
            raise TypeError("Неправильний тип значення або ключ")
