import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()
vt_api_key = os.getenv("VT_API_KEY")
vulner_api_key = os.getenv("VULNER_API_KEY")

def virus_total_request(api_key):
    """Возвращает JSON от VirusTotal для IP 8.8.8.8"""
    vt_resp = requests.get(
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
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
            "ip": "8.8.8.8",
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


def main():
    print("hello")
    
    # Получаем данные как JSON для обработки
    vulners_data = vulners_request(vulner_api_key)
    vt_data = virus_total_request(vt_api_key)
    
    print("Vulners данные получены:", vulners_data["status"])
    print("VT данные получены:", vt_data["status"])

    print (vt_data)
    
    # Теперь можно обработать данные дальше:
    # - сохранить в pandas
    # - проанализировать CVSS/reputation
    # - построить графики
    
    return {
        "vulners": vulners_data,
        "virustotal": vt_data
    }


if __name__ == "__main__":
    result = main()
    # result содержит все JSON для дальнейшей обработки
