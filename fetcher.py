import requests
from datetime import datetime, timedelta, timezone

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_recent_cves(hours: int = 24, max_results: int = 20) -> list[dict]:
    """
    Récupère les CVE publiées dans les dernières X heures
    depuis la base officielle NIST/NVD.
    """
    
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)
    
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": max_results,
        "startIndex": 0
    }
    
    print(f"🔍 Fetching CVEs from last {hours}h...")
    
    try:
        response = requests.get(
            NVD_BASE_URL,
            params=params,
            timeout=15,
            headers={"User-Agent": "ThreatIntelBot/1.0"}
        )
        response.raise_for_status()
        data = response.json()
        
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            
            # ID
            cve_id = cve.get("id", "Unknown")
            
            # Description anglaise
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )
            
            # Score CVSS
            score = None
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity", "UNKNOWN")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score = cvss.get("baseScore")
                severity = "HIGH" if score and score >= 7 else "MEDIUM"
            
            # Date de publication
            published = cve.get("published", "")[:10]
            
            # References
            refs = cve.get("references", [])
            ref_urls = [r["url"] for r in refs[:3]]
            
            cves.append({
                "id": cve_id,
                "description": description,
                "score": score,
                "severity": severity,
                "published": published,
                "references": ref_urls
            })
        
        print(f"✅ {len(cves)} CVEs found")
        return cves
        
    except requests.exceptions.Timeout:
        print("⚠️ NVD API timeout — try again in a few seconds")
        return []
    except Exception as e:
        print(f"❌ Error fetching CVEs: {e}")
        return []

def get_cve_by_id(cve_id: str) -> dict:
    """Récupère une CVE spécifique par son ID."""
    
    try:
        response = requests.get(
            NVD_BASE_URL,
            params={"cveId": cve_id.upper().strip()},
            timeout=15,
            headers={"User-Agent": "ThreatIntelBot/1.0"}
        )
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        
        if not vulns:
            return {"error": f"CVE {cve_id} not found"}
        
        cve = vulns[0].get("cve", {})
        
        # Description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available"
        )
        
        # Score CVSS
        score = None
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            score = cvss.get("baseScore")
            severity = cvss.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            score = cvss.get("baseScore")
            severity = "HIGH" if score and score >= 7 else "MEDIUM"

        # References
        refs = cve.get("references", [])
        ref_urls = [r["url"] for r in refs[:3]]
        
        return {
            "id": cve_id.upper(),
            "description": description,
            "score": score,
            "severity": severity,
            "published": cve.get("published", "")[:10],
            "references": ref_urls
        }
        
    except Exception as e:
        return {"error": str(e)}
