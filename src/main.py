import requests
import json
import os
from dotenv import load_dotenv
import pandas as pd

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
    """Возвращает JSON от Vulners с CVE высокого риска"""
    vulner_resp = requests.post(
        "https://vulners.com/api/v3/search/lucene",
        headers={
            "X-Api-Key": api_key,
            "Content-Type": "application/json"
        },
        json={
            "query": "type:cve AND cvss.score:[7 TO 10]", 
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
    
    # Читаем JSONL (JSON на каждой строке)
    logs_df = pd.read_json(log_path, lines=True)
    print(f"Загружено событий: {len(logs_df)}")
    
    return logs_df

def main():
    suricata_logs = read_suricata_logs()
    suspicious_ips = suricata_logs[suricata_logs['event_type']=='alert']['src_ip'].unique()
    for ip in suspicious_ips[:5]:  # первые 5
        vt_data = virus_total_request(vt_api_key,ip)  # замени 8.8.8.8 на реальный IP

    
    
    # Получаем данные как JSON для обработки
    #vulners_data = vulners_request(vulner_api_key)
    #vt_data = virus_total_request(vt_api_key)
    
    #print("Vulners данные получены:", vulners_data["status"])
    #print("VT данные получены:", vt_data["status"])

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
