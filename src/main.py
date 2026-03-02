import requests
import json
import os
import vulners
from dotenv import load_dotenv
import time 

load_dotenv()
vt_api_key = os.getenv("VT_API_KEY")
vulner_api_key = os.getenv("VULNER_API_KEY")


def main():
    print("hello")
    # Ищем CVE с высоким CVSS БЕЗ vulners SDK
    resp = requests.post(
        "https://vulners.com/api/v3/search/lucene",
        headers={
            "X-Api-Key": vulner_api_key,
            "Content-Type": "application/json"
        },
        json={
            "query": "type:cve AND cvss.score:[7 TO 10]", 
            "size": 5
        }
    )
    
    if resp.status_code == 200:
        data = resp.json()
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(f"Ошибка API: {resp.status_code} - {resp.text}")

if __name__ == "__main__":
    main()
