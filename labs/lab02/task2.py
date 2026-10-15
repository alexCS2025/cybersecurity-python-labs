import argparse
import csv
import json
import logging
import sys
from collections import defaultdict

SEVERITY_LEVELS = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

logger = logging.getLogger("edr_aggregator")


def setup_logging(log_file=None):
    handlers = [logger.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logger.FileHandler(log_file, encoding="utf-8"))

    logger.basicConfig(
        level=logger.INFO, format="[%(levelname)s] %(message)s", handlers=handlers
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Tool for aggregating incidents from EDR alerts"
    )
    parser.add_argument(
        "--edr-log", type=str, required=True, help="Path to EDR alerts JSON logs."
    )
    parser.add_argument(
        "--min-severity",
        type=str,
        choices=["Low", "Medium", "High", "Critical"],
        default="Low",
        help="Minimal severity of incident (default severity is Low)",
    )
    parser.add_argument(
        "--out-csv", type=str, default="labs/lab02/data", help="Path to save CSV report"
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Optional log file path to write execution and error logs",
    )
    return parser.parse_args()


def load_edr_logs(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except FileNotFoundError:
        logger.error(f"Файл '{filepath}' не знайдено.")
        sys.exit(1)
    except PermissionError:
        logger.error(f"Немає прав для читання файлу '{filepath}'.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(
            f"Файл '{filepath}' містить некоректний JSON (помилка на рядку {e.lineno}, колонка {e.colno}): {e.msg}"
        )
        sys.exit(1)
    except OSError as e:
        logger.error(f"Системна помилка вводу-виводу при читанні '{filepath}': {e}")
        sys.exit(1)


def export_to_csv(aggregated_matrix, output_path):
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Hostname", "ThreatName", "IncidentCount"])
            for (host, threat), count in sorted(aggregated_matrix.items()):
                writer.writerow([host, threat, count])

    except PermissionError:
        logger.error(
            f"Не вдалося зберегти CSV звіт: немає прав на запис у '{output_path}'."
        )
    except csv.Error as e:
        logger.error(f"Помилка при записі CSV даних у '{output_path}': {e}")
    except OSError as e:
        logger.error(
            f"Не вдалося зберегти CSV звіт у '{output_path}' (можливо, вказано неіснуючий каталог): {e}"
        )


def main():
    args = parse_args()
    setup_logging(args.log_file)

    logger.info(f"Aggregating EDR alerts from {args.edr_log}...")

    raw_events = load_edr_logs(args.edr_log)
    logger.info(f"Processed {len(raw_events)} antivirus incident events.")

    min_severity_rank = SEVERITY_LEVELS.get(args.min_severity, 1)

    severity_counts = defaultdict(int)
    host_threat_matrix = defaultdict(int)
    host_total_threats = defaultdict(int)
    unresolved_threats = []

    for event in raw_events:
        severity = event.get("Severity", "Low")
        severity_counts[severity] += 1

        if SEVERITY_LEVELS.get(severity, 1) < min_severity_rank:
            continue

        hostname = event.get("Hostname", "Unknown")
        threat_name = event.get("ThreatName", "Unknown")
        action_taken = event.get("ActionTaken", "")

        host_threat_matrix[(hostname, threat_name)] += 1
        host_total_threats[hostname] += 1

        if action_taken not in ["Quarantined", "Deleted"]:
            unresolved_threats.append(event)

    print("\nSeverity Distribution")
    for sev in ["Critical", "High", "Medium", "Low"]:
        print(f"{sev:<8} : {severity_counts[sev]}")

    print("\nUnresolved Security Threats (Action Not Quarantined/Deleted)")
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

    print("\nTop Affected Hosts")
    sorted_hosts = sorted(host_total_threats.items(), key=lambda x: x[1], reverse=True)
    for idx, (host, count) in enumerate(sorted_hosts[:5], start=1):
        print(f"{idx}. {host} ({count} threats)")

    print()
    export_to_csv(host_threat_matrix, args.out_csv)
    logger.info(f"Aggregated incident matrix saved to {args.out_csv}")


if __name__ == "__main__":
    main()
