В рамках учебного задания подготовлена система анализа угроз для обнаружения подозрительной активности на основе логов Suricata и внешних API (VirusTotal, Vulners).

## Архитектура

```
lessons_fin/
├── src/
│   ├── main.py                    # Точка входа, оркестрация анализа
│   ├── analyzers/
│   │   ├── suricata_reader.py     # Чтение JSON логов Suricata
│   │   └── threat_analyzer.py     # Анализ угроз (VT, Vulners, Suricata)
│   ├── api/
│   │   ├── virustotal.py          # API запросы к VirusTotal
│   │   └── vulners.py             # API запросы к Vulners
│   └── reporters/
│       └── report.py              # Генерация CSV и PNG отчётов
├── src/suricata_logs/
│   └── honeypot-2018/
│       └── eve.json               # Логи Suricata
├── reports/
│   ├── threats.csv                # Отчёт в CSV
│   └── top_ips.png               # График топ-5 IP
├── .env                          # API ключи (VT_API_KEY, VULNER_API_KEY)
├── requirements.txt
└── README.md
```

## Функционал

### 1. Чтение логов Suricata
- Формат: JSON (eve.json)
- Источник: `src/suricata_logs/honeypot-2018/eve.json`
- Поля: `event_type`, `src_ip`, `alert`, `dns`

### 2. Анализ угроз

**Vulners API** — поиск CVE уязвимостей:
- Поиск по идентификатору CVE (например, `CVE-2024-21762`)
- Фильтрация по CVSS-баллу (>= 7.0 = высокий риск)

**VirusTotal API** — проверка репутации IP:
- Проверка `last_analysis_stats` (malicious, suspicious, harmless)
- Расчёт риска на основе количества обнаружений

**Suricata логи**:
- Обнаружение подозрительных IP (по количеству алертов)
- Обнаружение DNS-туннелей (частые DNS-запросы > 20)

### 3. Реагирование на угрозы
Имитация действий при обнаружении:
- `SUSPICIOUS_IP` → `iptables -A INPUT -s IP -j DROP`
- `VT_MALICIOUS` → критический уровень угрозы
- `CVE_HIGH_RISK` → рекомендуемое действие "патчить"

### 4. Отчёты
- **CSV**: Сохранение всех найденных угроз
- **PNG**: График топ-5 подозрительных IP

## Установка

```bash
# Установка зависимостей
pip install -r requirements.txt

# Настройка API ключей
cp .env.example .env
# VT_API_KEY=your_virustotal_key
# VULNER_API_KEY=your_vulners_key
```

## Запуск

```bash
python src/main.py
```

## Зависимости

- `pandas` — работа с данными
- `requests` — HTTP запросы
- `matplotlib` / `seaborn` — визуализация
- `python-dotenv` — загрузка переменных окружения
- `vulners` — клиент API Vulners
- `appdirs` — определение директорий

## Задание 

1. **Сбор данных**: Три источника (VirusTotal, Vulners, Suricata)
2. **Анализ**: Поиск опасных уязвимостей, подозрительных IP, DNS-туннелей
3. **Реагирование**: Имитация блокировки IP и уведомлений
4. **Отчёты**: CSV + PNG график топ-5 IP
