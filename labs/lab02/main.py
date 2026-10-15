import argparse
import logging
import sys
from pathlib import Path

try:
    from labs.lab02.task1 import (
        Admin,
        AuditLog,
        User,
        UserAccount,
    )
    from labs.lab02.task2 import (
        SEVERITY_LEVELS,
        export_to_csv,
        load_edr_logs,
        setup_logging,
    )
except ImportError:
    from task1 import (
        Admin,
        AuditLog,
        User,
        UserAccount,
    )
    from task2 import (
        SEVERITY_LEVELS,
        export_to_csv,
        load_edr_logs,
        setup_logging,
    )

logger = logging.getLogger("main_logger")


def run_demo() -> None:
    """Запускає повний демонстраційний сценарій ООП із task1.py."""
    print("=" * 65)
    print("=== DEMO: Демонстрація ООП Моделей (Завдання 1) ===")
    print("=" * 65 + "\n")

    print("1. Створення користувача та встановлення пароля:")
    user = User(
        username="analyst_john",
        email="john.doe@security.corp",
        role="analyst",
    )
    
    user.set_password("SuperSecurePass2026!")
    print(f"   Створено користувача: {user.username} (Email: {user.email})")

    audit_log = AuditLog()
    account = UserAccount(user=user, audit_log=audit_log)

    print("\n2. Автентифікація (Login Attempts):")
    fail_result = account.login("WrongPassword123", "192.168.1.100")
    print(
        f"   Спроба входу з невірним паролем: {'УСПІХ' if fail_result else 'НЕВДАЧА'}"
    )

    success_result = account.login("SuperSecurePass2026!", "192.168.1.100")
    print(
        f"   Спроба входу з вірним паролем:   {'УСПІХ' if success_result else 'НЕВДАЧА'}"
    )
    print(f"   Статус авторизації (is_authenticated): {account.is_authenticated()}")

    print("\n3. Управління Сесією (Session & Timeout):")
    if account.session:
        print(f"   IP адреса сесії: {account.session.ip}")
        print(
            f"   Час останньої активності: {account.session.last_activity.isoformat()}"
        )
        print(f"   Сесія активна (timeout=900s): {account.session.is_active(900)}")
        account.session.touch()
        print("   Викликано session.touch() — час оновлено.")

    print("\n4. Валідація Email:")
    try:
        user.email = "invalid_email_with_#bad_symbol"
    except ValueError as e:
        print(f"   [Перехоплено помилку валідації]: {e}")

    user.email = "john.updated@security.corp"
    print(f"   Успішно оновлено email: {user.email}")

    print("\n5. Адміністрування (Клас Admin):")
    admin = Admin(
        username="ciso_admin",
        email="admin@security.corp",
        role="admin",
    )
    admin.set_password("AdminRootKey2026#")
    admin.grant_permission("READ_EDR_LOGS")
    admin.grant_permission("MANAGE_USERS")
    print(f"   Права адміністратора {admin.username}: {admin.permissions}")
    print(f"   Чи має право 'READ_EDR_LOGS': {admin.has_permission('READ_EDR_LOGS')}")
    admin.revoke_permission("MANAGE_USERS")
    print(f"   Після вилучення 'MANAGE_USERS': {admin.permissions}")

    print("\n6. Завершення сеансу та Журнал Аудиту (AuditLog):")
    account.logout()
    print(f"   Статус авторизації після logout: {account.is_authenticated()}")

    account.audit_log.show_all()
    print("\n=== Демонстрацію Завдання 1 завершено ===\n")


def run_analyze(
    edr_log: str,
    min_severity: str = "Low",
    out_csv: str = "labs/lab02/data/edr_summary.csv",
    log_file: str | None = None,
) -> None:
    """Виконує запуск аналізатора логів EDR з task2.py."""
    setup_logging(log_file)

    logger.info(f"Aggregating EDR alerts from {edr_log}...")

    edr_path = Path(edr_log)
    if not edr_path.exists():
        logger.error(f"Файл логів EDR не знайдено: {edr_log}")
        sys.exit(1)

    raw_events = load_edr_logs(str(edr_path))
    logger.info(f"Processed {len(raw_events)} antivirus incident events.")

    min_severity_rank = SEVERITY_LEVELS.get(min_severity, 1)

    severity_counts: dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    host_threat_matrix: dict[tuple[str, str], int] = {}
    host_total_threats: dict[str, int] = {}
    unresolved_threats: list[dict] = []

    for event in raw_events:
        severity = event.get("Severity", "Low").capitalize()
        if severity in severity_counts:
            severity_counts[severity] += 1

        if SEVERITY_LEVELS.get(severity, 1) < min_severity_rank:
            continue

        hostname = event.get("Hostname", "Unknown")
        threat_name = event.get("ThreatName", "Unknown")
        action_taken = event.get("ActionTaken", "")

        pair = (hostname, threat_name)
        host_threat_matrix[pair] = host_threat_matrix.get(pair, 0) + 1
        host_total_threats[hostname] = host_total_threats.get(hostname, 0) + 1

        if action_taken not in ["Quarantined", "Deleted"]:
            unresolved_threats.append(event)

    # Вивід результатів аналізу у консоль
    print("\n=== Severity Distribution ===")
    for sev in ["Critical", "High", "Medium", "Low"]:
        print(f"{sev:<8} : {severity_counts[sev]}")

    print("\n=== Unresolved Security Threats (Action Not Quarantined/Deleted) ===")
    if not unresolved_threats:
        print("No unresolved threats found.")
    else:
        for threat in unresolved_threats:
            sev_tag = f"[{threat.get('Severity', 'INFO').upper()}]"
            host = threat.get("Hostname", "N/A")
            th_name = threat.get("ThreatName", "N/A")
            action = threat.get("ActionTaken", "N/A")
            print(
                f"{sev_tag:<11} Host: {host:<15} | Threat: {th_name:<25} | Action: {action}"
            )

    print("\n=== Top Affected Hosts ===")
    sorted_hosts = sorted(host_total_threats.items(), key=lambda x: x[1], reverse=True)
    for idx, (host, count) in enumerate(sorted_hosts[:5], start=1):
        print(f"{idx}. {host} ({count} threats)")

    print()
    export_to_csv(host_threat_matrix, out_csv)
    logger.info(f"Aggregated incident matrix saved to {out_csv}")


def parse_args() -> argparse.Namespace:
    """Створює та налаштовує парсер аргументів CLI."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Консольна утиліта кібербезпеки (Лабораторна №2, Варіант 14)",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Оберіть команду для виконання",
    )

    # Підкоманда demo
    subparsers.add_parser(
        "demo",
        help="Запустити демонстрацію ООП класів",
    )

    # Підкоманда analyze
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Запустити аналіз та агрегацію EDR-логів",
    )
    analyze_parser.add_argument(
        "--edr-log",
        type=str,
        default="labs/lab02/data/edr_alerts.json",
        help="Шлях до вхідного JSON-файлу з логами EDR (default: labs/lab02/data/edr_events.json)",
    )
    analyze_parser.add_argument(
        "--min-severity",
        type=str,
        choices=["Low", "Medium", "High", "Critical"],
        default="Low",
        help="Мінімальний рівень критичності загроз (default: Low)",
    )
    analyze_parser.add_argument(
        "--out-csv",
        type=str,
        default="labs/lab02/data/edr_summary.csv",
        help="Шлях для збереження підсумкового CSV-звіту (default: labs/lab02/data/edr_summary.csv)",
    )
    analyze_parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Опціональний шлях до файлу системного логу утиліти",
    )

    return parser.parse_args()


def main() -> None:
    """Головна функція виконання."""
    args = parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_analyze(
            edr_log=args.edr_log,
            min_severity=args.min_severity,
            out_csv=args.out_csv,
            log_file=args.log_file,
        )


if __name__ == "__main__":
    main()
