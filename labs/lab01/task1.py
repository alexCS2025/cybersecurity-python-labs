import os
import random
import string
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared import student

passwords = [
    "C2@Command",
    "plain123",
    "Backdoor@D3tect",
    "public123",
    "Rootk1t@Hunt",
    "access123",
    "Exploit@An4lysis",
    "basic",
    "Payload@D3code",
    "default123",
]
criteria = {
    "min_length": 10,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {
    "plain123",
    "public123",
    "access123",
    "basic",
    "default123",
    "user",
}


print(len(passwords))
for i in range(3):
    x = random.randint(0, len(passwords) - 1)
    passwords.append(passwords[x])


def evaluate_password(password, all_passwords):
    """Evaluate the strength of your password"""
    min_len = criteria["min_length"]

    if password in forbidden_passwords or len(password) < min_len:
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(char in string.punctuation for char in password)

    active_checks = [has_lower]
    if criteria["require_digits"]:
        active_checks.append(has_digit)
    if criteria["require_upper"]:
        active_checks.append(has_upper)
    if criteria["require_special"]:
        active_checks.append(has_special)

    passed_checks = sum(active_checks)
    total_checks = len(active_checks)
    meets_all = passed_checks == total_checks

    is_unique = all_passwords.count(password) == 1

    if meets_all and len(password) >= min_len + 4 and is_unique:
        return "Дуже сильний"

    if meets_all:
        return "Сильний"

    if passed_checks > 1:
        return "Середній"

    return "Слабкий"


def main():
    print(f"Студент: {student.STUDENT_NAME} | Варіант №{student.VARIANT_NUMBER}\n")
    print(f"{'№':<3} | {'Пароль':<20} | {'Оцінка надійності':<15}")
    print("-" * 45)

    for idx, pwd in enumerate(passwords, start=1):
        result = evaluate_password(pwd, passwords)
        print(f"{idx:<3} | {pwd:<20} | {result:<15}")

main()
