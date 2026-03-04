import pandas as pd

def analyze_vt_reputation(vt_data: dict) -> dict:
    """Извлекает ключевые метрики репутации IP из VirusTotal."""
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
    """Анализирует логи Suricata и данные API на наличие угроз."""
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

    # Подозрительные IP из Suricata
    alerts = suricata_logs[suricata_logs['event_type'] == 'alert']
    top_ips = alerts['src_ip'].value_counts().head(5)
    for ip, count in top_ips.items():
        threats.append({
            "type": "SUSPICIOUS_IP",
            "ip": ip,
            "alerts_count": count,
            "severity": "high" if count > 10 else "medium"
        })
    
    # Частые DNS-запросы (возможный туннель)
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