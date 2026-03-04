import os
from dotenv import load_dotenv

from api.virustotal import virus_total_request
from api.vulners import vulners_request
from analyzers.suricata_reader import read_suricata_logs
from analyzers.threat_analyzer import analyze
from reporters.report import save_report


def react_to_threats(threats):
    """Имитирует реагирование на обнаруженные угрозы."""
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

def main():
    """Главная функция: оркестрация анализа логов и API-запросов."""
    load_dotenv()
    vt_api_key = os.getenv("VT_API_KEY")
    vulner_api_key = os.getenv("VULNER_API_KEY")

    suricata_logs = read_suricata_logs()
           
    # Запрос в vulners по CVE 
    vulners_data = vulners_request(vulner_api_key,"CVELIST:CVE-2024-21762")
    
    # Запрос в VirusTotal по IP из Suricata
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

if __name__ == "__main__":
    result = main()
