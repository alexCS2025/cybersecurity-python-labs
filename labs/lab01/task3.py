import csv
import hashlib
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared import student

SALT = str(student.VARIANT_NUMBER).zfill(5)

DATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../labs/lab01/data")
)

USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGHT = 16

users_to_register = (
    ("admin_user", "SuperSecretPass123!"),
    ("crypto_dev", "SecureBlockchain2026#"),
    ("smart_auditor", "AuditPass321!@#"),
    ("trader_pro", "TradingPass999999"),
    ("wallet_holder", "MyWalletPass1234"),
    ("node_operator", "ValidatorNode2026"),
    ("security_lead", "CisoPassWord1234"),
    ("devops_engineer", "DeployPipeline26"),
    ("analyst_user", "MarketDataPass123"),
    ("guest_account", "GuestAccess2026!"),
)

users_db = []


class ValidationError(Exception):
    """Password validation error"""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Generates hash for password using sha512 and salt"""
    if password is None or salt is None or password == "" or salt == "":
        raise ValueError("Password and salt cannot be empty!")

    if len(password) < MIN_PASSWORD_LENGHT:
        raise ValidationError(
            f"Password is too short (minimum {MIN_PASSWORD_LENGHT} characters required, got {len(password)})!"
        )
    hash = hashlib.sha512()
    hash.update(salt.encode("utf-8"))
    hash.update(password.encode("utf-8"))

    return hash.hexdigest()


def create_user(username: str, password: str) -> tuple:
    """Creates a tuple of (username, hash_value)"""
    hash_val = generate_hash(password, SALT)
    return (username, hash_val)


def create_users(users_list: tuple) -> None:
    """Creates user database in users.csv file."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)

        with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password_hash"])
            for user, pwd in users_list:
                try:
                    u_tuple = create_user(user, pwd)
                    writer.writerow(u_tuple)
                except (ValidationError, ValueError) as e:
                    print(f"{user} not created. Error: {e}")
    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"File system error occurred when creating users: {e}")


def read_users_db() -> list:
    """Reads CSV file content, lists and displays the table"""
    db = []

    try:
        with open(USERS_CSV_PATH, mode="r", encoding="utf-8") as file:
            reader = csv.reader(file)
            next(reader, None)
            for row in reader:
                if row:
                    db.append((row[0], row[1]))

        print("User Database")
        print(f"{'Username':<20} | {'Password Hash (SHA512)'}")
        print("-" * 70)
        for user, hash in db:
            print(f"{user:<20} | {hash[:35]}...")
        print("\n")
        return db
    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"File system error while reading users DB: {e}")


def log_event(func):
    """Decorator for logging login attempts into log.json file"""

    def wrapper(username, password, *args, **kwargs):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except (OSError, PermissionError) as e:
            print(f"Directory creation error for logs: {e}")

        result_status = "failure"
        try:
            res = func(username, password, *args, **kwargs)
            if res:
                result_status = "success"
            return res
        except Exception:
            result_status = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": result_status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            logs = []
            try:
                if os.path.exists(LOG_JSON_PATH):
                    try:
                        with open(LOG_JSON_PATH, mode="r", encoding="utf-8") as f:
                            logs = json.load(f)
                    except (OSError, json.JSONDecodeError):
                        logs = []

                logs.append(log_entry)

                with open(LOG_JSON_PATH, mode="w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except (OSError, FileNotFoundError, PermissionError) as e:
                print(f"File system error while logging event: {e}")

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Authenticates the user in the database"""
    try:
        if not username or not password:
            raise ValueError("Username and password cannot be empty!")

        input_hash = generate_hash(password, SALT)

        for db_user, db_hash in users_db:
            if db_user == username:
                return db_hash == input_hash

        return False
    except (ValidationError, ValueError) as e:
        print(f"Authentication error for '{username}': {e}")
        return False


def main():
    global users_db

    create_users(users_to_register)
    users_db = read_users_db()

    valid_user, valid_pass = users_to_register[0]
    is_authenticated = login(valid_user, valid_pass)
    print(f"Login attempt for '{valid_user}': {is_authenticated}")

    invalid_pass = "blablabla"
    is_authenticated = login(valid_user, invalid_pass)
    print(f"Login attempt for '{valid_user}': {is_authenticated}")

    is_authenticated = login("gogogo", "SomePassword12345!")
    print(f"Login attempt for 'gogogo': {is_authenticated}")


main()