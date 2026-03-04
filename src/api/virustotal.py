import requests

def virus_total_request(vt_api_key: str, ip: str) -> dict[str, any]:
    """Запрос VirusTotal API для анализа IP-адреса."""
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
