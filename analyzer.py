import json
import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
You are a senior cybersecurity analyst specializing in vulnerability intelligence.
Your role is to translate technical CVE data into clear, actionable intelligence 
for IT teams and security professionals.

Always respond in English. Be precise, concise, and actionable.
"""

def analyze_cve(cve: dict) -> dict:
    """GPT analyse une CVE et produit un rapport actionnable."""
    
    prompt = f"""
Analyze this CVE and produce an intelligence report:

CVE ID: {cve['id']}
Severity: {cve['severity']} (Score: {cve['score']}/10)
Published: {cve['published']}
Description: {cve['description']}

Return ONLY this JSON without backticks:
{{
    "title": "Short title describing what is vulnerable",
    "impact": "What can an attacker do if this is exploited?",
    "affected_systems": "What systems/software are at risk?",
    "recommended_action": "What should IT teams do right now?",
    "urgency": "IMMEDIATE | HIGH | MEDIUM | LOW",
    "executive_summary": "2 sentences for a non-technical manager"
}}
"""
    
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2,
        max_tokens=500
    )
    
    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    
    analysis = json.loads(raw)
    
    return {**cve, **analysis}


def analyze_batch(cves: list[dict], max_analyze: int = 10) -> list[dict]:
    """
    Analyse un batch de CVE.
    Priorise les plus sévères, limite les appels API.
    """
    
    # Trie par score décroissant
    sorted_cves = sorted(
        cves,
        key=lambda x: x.get("score") or 0,
        reverse=True
    )
    
    # Analyse seulement les N plus critiques
    to_analyze = sorted_cves[:max_analyze]
    
    results = []
    for i, cve in enumerate(to_analyze):
        print(f"🧠 Analyzing {i+1}/{len(to_analyze)}: {cve['id']}")
        try:
            analyzed = analyze_cve(cve)
            results.append(analyzed)
        except Exception as e:
            print(f"⚠️ Error analyzing {cve['id']}: {e}")
            results.append(cve)
    
    return results