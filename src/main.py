import requests
import json
import os
from dotenv import load_dotenv
import pandas as pd
import matplotlib.pyplot as plt

load_dotenv()
vt_api_key = os.getenv("VT_API_KEY")
vulner_api_key = os.getenv("VULNER_API_KEY")

def virus_total_request(api_key:str, ip:str ):
    vt_resp = requests.get(
        "https://www.virustotal.com/api/v3/ip_addresses/"+ip,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    )
    
    if vt_resp.status_code == 200:
        vt_data = vt_resp.json()
        # Возвращаем только полезные данные для анализа
        return {
            "status": "success",
            "ip": ip,
            "attributes": vt_data['data']['attributes']
        }
    else:
        return {
            "status": "error",
            "code": vt_resp.status_code,
            "message": vt_resp.text
        }


def vulners_request(api_key):
    """Возвращает список CVE по простой строке поиска"""
    vulner_resp = requests.post(
        "https://vulners.com/api/v3/search/lucene",
        headers={
            "X-Api-Key": api_key,
            "Content-Type": "application/json"
        },
        json={
            "query": "type:cve AND Microsoft",   # или Linux, Apache, Fortinet и т.п.
            "size": 5
        }
    )

    if vulner_resp.status_code == 200:
        data = vulner_resp.json()
        return {
            "status": "success",
            "total": data.get("total", 0),
            "search": data.get("search", [])
        }
    else:
        return {
            "status": "error",
            "code": vulner_resp.status_code,
            "message": vulner_resp.text
        }


def read_suricata_logs():
    """Читает Suricata eve.json из src/suricata_logs/honeypot-2018/"""
    current_dir = os.path.dirname(os.path.abspath(__file__))  # /.../lessons_fin/src
    project_root = os.path.dirname(current_dir)                # /.../lessons_fin
    log_path = os.path.join(project_root, "suricata_logs", "honeypot-2018", "eve.json")
    print(f"Читаем логи: {log_path}")
  
    # Проверяем существование файла
    if not os.path.exists(log_path):
        return None
    
    # Читаем JSON
    logs_df = pd.read_json(log_path, lines=True)
    print(f"Загружено событий: {len(logs_df)}")
    return logs_df

def analyze(suricata_logs, vulners_data, vt_data):
    """Анализирует логи и API данные на угрозы"""
    threats = []
    
    # 1. ОПАСНЫЕ УЯЗВИМОСТИ — ИСПРАВЛЕНО
    high_risk_cve = pd.DataFrame()  # ← ИНИЦИАЛИЗИРУЕМ ПУСТЫМ
    
    if vulners_data["total"] > 0:
        high_cve = pd.DataFrame(vulners_data["search"])
        # Безопасно проверяем наличие колонки CVSS
        if 'cvss.score' in high_cve.columns:
            high_risk_cve = high_cve[high_cve['cvss.score'] >= 7.0]
        else:
            high_risk_cve = high_cve  # Берём все CVE
        
        for _, cve in high_risk_cve.iterrows():
            threats.append({
                "type": "CVE_HIGH_RISK",
                "id": cve.get('id', 'N/A'),
                "cvss": cve.get('cvss.score', 'N/A'),
                "title": cve.get('title', 'N/A')
            })
    else:
        threats.append({
            "type": "INFO",
            "message": f"Vulners: CVE не найдено (total={vulners_data['total']})"
        })
    
    # 2. ПОДОЗРИТЕЛЬНЫЕ IP из Suricata
    alerts = suricata_logs[suricata_logs['event_type'] == 'alert']
    top_ips = alerts['src_ip'].value_counts().head(5)
    for ip, count in top_ips.items():
        threats.append({
            "type": "SUSPICIOUS_IP",
            "ip": ip,
            "alerts_count": count,
            "severity": "high" if count > 10 else "medium"
        })
    
    # 3. ЧАСТЫЕ DNS-запросы
    dns_logs = suricata_logs[suricata_logs['event_type'] == 'dns']
    if len(dns_logs) > 0:
        dns_spam = dns_logs.groupby('src_ip').size()
        suspicious_dns = dns_spam[dns_spam > 20].index.tolist()
        for ip in suspicious_dns:
            threats.append({
                "type": "DNS_TUNNEL",
                "ip": ip,
                "dns_count": int(dns_spam[ip])
            })
    
    return threats

def react_to_threats(threats):
    """Этап 3: Имитация реагирования"""
    for threat in threats:
        if threat['type'] == 'SUSPICIOUS_IP':
            ip = threat['ip']
            severity = threat['severity']
            print(f"\n РЕАГИРОВАНИЕ на {ip} (severity: {severity})")
            print(f"  $ sudo iptables -A INPUT -s {ip} -j DROP")
            print(f"  $ Telegram: БЛОКИРОВКА IP {ip}")
            
        elif threat['type'] == 'CVE_HIGH_RISK':
            print(f"\n CVE {threat['id']}: Срочно патчить!")
            
    print("\n Реагирование завершено")
    return threats

def save_report(threats):
    """Этап 4: CSV + график топ-5 IP"""
    
    # 1. СОЗДАЁМ ПАПКУ reports/
    current_dir = os.path.dirname(os.path.abspath(__file__))  # /.../src
    project_root = os.path.dirname(current_dir)               # /.../lessons_fin
    reports_dir = os.path.join(project_root, "reports")
    
    os.makedirs(reports_dir, exist_ok=True)  # ← СОЗДАЁТ ПАПКУ АВТОМАТИЧЕСКИ
    print(f"Создан reports: {reports_dir}")
    
    # 2. Сохраняем CSV
    df_threats = pd.DataFrame(threats)
    csv_path = os.path.join(reports_dir, "threats.csv")
    df_threats.to_csv(csv_path, index=False)
    print(f"Отчёт: {csv_path}")
    
    # 3. График ТОП-5 IP
    ip_threats = [t for t in threats if t['type'] == 'SUSPICIOUS_IP']
    if ip_threats:
        ips = [t['ip'] for t in ip_threats]
        counts = [t['alerts_count'] for t in ip_threats]
        
        plt.figure(figsize=(10,6))
        plt.bar(ips, counts, color='red', alpha=0.7)
        plt.title('Топ-5 подозрительных IP (по алертам Suricata)')
        plt.xlabel('IP-адрес')
        plt.ylabel('Количество алертов')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        png_path = os.path.join(reports_dir, "top_ips.png")
        plt.savefig(png_path, dpi=300, bbox_inches='tight')
        plt.show()
        print(f"График: {png_path}")
    else:
        print("Нет IP-угроз для графика")
    



def main():
    suricata_logs = read_suricata_logs()
    suspicious_ips = suricata_logs[suricata_logs['event_type']=='alert']['src_ip'].unique()
           
    # Получаем JSON по API для обработки, в virus total для теста 5 IP-адресов 
    vulners_data = vulners_request(vulner_api_key)
    for ip in suspicious_ips[:5]:  
        vt_data = virus_total_request(vt_api_key,ip)  


    print("Vulners данные получены:", vulners_data["status"])
    print("VT данные получены:", vt_data["status"])

    threats = analyze(suricata_logs,vulners_data,vt_data)

    print(f"\n НАЙДЕНО УГРОЗ: {len(threats)}")
    for threat in threats:
        print(f"• {threat['type']}: {threat}")

    react_to_threats(threats)
    save_report(threats)
    # Теперь можно обработать данные дальше:
    # - сохранить в pandas
    # - проанализировать CVSS/reputation
    # - построить графики
    
    #return {
    #    "vulners": vulners_data,
    #    "virustotal": vt_data
    #}


if __name__ == "__main__":
    result = main()
    # result содержит все JSON для дальнейшей обработки
