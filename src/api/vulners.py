import requests

def vulners_request(vulner_api_key: str, cve_key: str) -> dict[str, any]:
    """Запрос Vulners API для поиска CVE по идентификатору."""
    vulner_url = "https://vulners.com/api/v3/search/id/"
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": vulner_api_key  
    }
    data = {
        "id": [cve_key]
    }
    vulner_resp = requests.post(vulner_url, headers=headers, json=data)

    if vulner_resp.status_code == 200:
        data = vulner_resp.json()
        documents = data["data"]["documents"]
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
