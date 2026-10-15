# Лабораторна робота №2: Розробка консольних утиліт для задач кібербезпеки

Варіант №14: Агрегатор інцидентів та сповіщень EDR / Антивіруса

---

## 1. Загальна інформація

* Студент: Курах Олександр Юрійович
* Група: КБ-208
* Варіант: №14

---

## 2. Установлення залежностей та налаштування середовища

Для роботи потрібен Python 3.10+ та активоване віртуальне середовище (`.venv`).


1. Активація віртуального середовища
Для macOS/Linux:
source .venv/bin/activate

Для Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

2. Встановлення/оновлення залежностей проєкту
pip install -r requirements.txt

## 3. Структура файлів з каталогу lab2_data
  
edr_alerts.json

Приклад запису показано нижче

  {
    "AlertID": "A-1001",
    "Timestamp": "2026-09-27T08:10:00",
    "Hostname": "WS-001",
    "ThreatName": "EICAR-Test-File",
    "Severity": "Low",
    "ActionTaken": "Deleted"
  }

## 4. Інструкції із запуску
Усі модулі слід запускати з кореневої директорії репозиторію через python -m.

1. Демонстрація Завдання 1
Запуск демонстраційного сценарію перевірки роботи класів User, Admin, Session, @dataclass AuditRecord та UserAccount:

python -m labs.lab02.main demo

2. Аналіз EDR-логів як усталено (default) (Завдання 2 — Варіант 14):

python -m labs.lab02.main analyze

3. Розширений запуск аналізу EDR-логів з усім набором CLI-параметрів:

python -m labs.lab02.main analyze --edr-log labs/lab02/data/edr_events.json --min-severity High --out-csv labs/lab02/data/edr_summary.csv --log-file labs/lab02/data/app.log

## 5. Пояснення CLI аргументів
Команда demo
Запускає ізольований демонстраційний сценарій першого завдання (моделювання безпечних сесій, хешування PBKDF2 HMAC SHA-256, перевірку таймауту сесії UTC, валідацію email через @property та перевірку адмін-прав).

Команда analyze
--edr-log: Шлях до вхідного JSON-файлу логів EDR (Усталено: labs/lab02/data/edr_events.json).

--min-severity: Фільтр мінімального рівня критичності загроз (Low, Medium, High, Critical) (Усталено: Low).

--out-csv: Шлях для експорту підсумкового CSV-звіту (Усталено: labs/lab02/data/edr_summary.csv).

--log-file: Опціональний шлях для збереження системного журналу виконання програми.

