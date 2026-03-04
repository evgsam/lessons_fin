import requests
import json
import os
from dotenv import load_dotenv
import pandas as pd
import matplotlib.pyplot as plt
import vulners


def virus_total_request(vt_api_key: str, ip: str) -> dict[str, any]:
    vt_resp = requests.get(
        "https://www.virustotal.com/api/v3/ip_addresses/"+ip,
        headers={
            "x-apikey": vt_api_key,
            "Accept": "application/json"
        }
    )
    
    if vt_resp.status_code == 200:
        vt_data = vt_resp.json()
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

def vulners_request(vulner_api_key: str, cve_key:str) -> dict[str, any]:
    cve_key = ''
    vulner_url = "https://vulners.com/api/v3/search/id/"
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": vulner_api_key  
    }
    data = {
        "id": [cve_key]
    }
    vulner_resp  = requests.post(vulner_url, headers=headers, json=data)

    if vulner_resp.status_code == 200:
        data = vulner_resp.json()
        documents= data["data"]["documents"]
        documents_list = []
        for key, doc in documents.items():
            doc_copy = doc.copy()
            doc_copy['vulners_key'] = key
            documents_list.append(doc_copy)
        return {
            "status": "success",
            "total": len(documents_list),  
            "search": documents_list        
        }
    else:
        return {
            "status": "error",
            "code": vulner_resp.status_code,
            "message": vulner_resp.text
        }


def read_suricata_logs() -> pd.DataFrame:
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


def analyze_vt_reputation(vt_data: dict) -> dict:
    """Извлекает ключевые метрики VirusTotal"""
    if vt_data['status'] != 'success':
        return {"reputation": "unknown", "risk": "low"}
    
    attributes = vt_data['attributes']
    stats = attributes.get('last_analysis_stats', {})
    
    # Подсчёт рисков
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    reputation = attributes.get('reputation', 0)
    
    # Оценка риска
    risk_score = malicious * 10 + suspicious * 3 - reputation
    risk_level = "high" if risk_score > 20 else "medium" if risk_score > 5 else "low"
    
    return {
        "malicious": malicious,
        "suspicious": suspicious, 
        "reputation": reputation,
        "risk_score": risk_score,
        "risk_level": risk_level
    }

def analyze(suricata_logs: pd.DataFrame, vulners_data: dict[str, any], vt_data: dict[str, any]):
    """Анализирует логи и API данные на угрозы"""
    threats = []
    high_risk_cve = pd.DataFrame()  
    
    if vulners_data["total"] > 0:
        high_cve = pd.DataFrame(vulners_data["search"])
       
        def extract_cvss_score(doc):
            if isinstance(doc, dict) and 'cvss' in doc and isinstance(doc['cvss'], dict):
                return doc['cvss'].get('score')
            return None

        if not high_cve.empty:
            high_cve['cvss_score'] = high_cve.apply(lambda row: extract_cvss_score(row.to_dict()), axis=1)
            high_cve['cvss_score'] = pd.to_numeric(high_cve['cvss_score'], errors='coerce')
        
        # Фильтруем по CVSS >= 7.0
            high_risk_mask = high_cve['cvss_score'].notna() & (high_cve['cvss_score'] >= 7.0)
            high_risk_cve = high_cve[high_risk_mask]
        
            if not high_risk_cve.empty:
                for _, cve in high_risk_cve.iterrows():
                    threats.append({
                        "type": "CVE_HIGH_RISK",
                        "id": cve.get('id', 'N/A'),
                        "cvss": cve['cvss_score'],
                        "title": cve.get('title', 'N/A')
                    })
            else:
                threats.append({
                    "type": "INFO",
                    "message": "Vulners: высокорисковых CVE (CVSS >= 7.0) не найдено"
                })
        else:       
            threats.append({
            "type": "INFO",
            "message": "Vulners: DataFrame пуст"
            })
    else:
        threats.append({
            "type": "INFO",
            "message": f"Vulners: CVE не найдено (status={vulners_data.get('status', 'unknown')}, total={vulners_data.get('total', 0)})"
        })
    
    if vt_data['status'] == 'success':
        vt_analysis = analyze_vt_reputation(vt_data)
        
        # Добавляем в угрозы
        threats.append({
            "type": "VT_REPUTATION",
            "ip": vt_data['ip'],
            "malicious": vt_analysis['malicious'],
            "suspicious": vt_analysis['suspicious'],
            "reputation": vt_analysis['reputation'],
            "risk_level": vt_analysis['risk_level']
        })
        
        # Если IP malicious → HIGH угроза
        if vt_analysis['malicious'] > 0:
            threats.append({
                "type": "VT_MALICIOUS",
                "ip": vt_data['ip'],
                "severity": "CRITICAL",
                "reason": f"{vt_analysis['malicious']} malicious detections"
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
    load_dotenv()
    vt_api_key = os.getenv("VT_API_KEY")
    vulner_api_key = os.getenv("VULNER_API_KEY")

    suricata_logs = read_suricata_logs()
           
    # Запрос в vulners по СVE 
    vulners_data = vulners_request(vulner_api_key,"CVELIST:CVE-2024-21762")
    
    #Запрос в virus totla по IP из сурикаты
    suspicious_ips = suricata_logs[suricata_logs['event_type']=='alert']['src_ip'].unique()
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
