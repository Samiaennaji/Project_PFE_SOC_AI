import os
import json
import hashlib
from typing import Optional

SYSTEM_PROMPT = """
You are a senior SOC analyst (Tier-2) specialized in:
- Wazuh SIEM alert triage and incident response
- MITRE ATT&CK framework mapping
- Network threat detection (brute-force, scanning, lateral movement, injection)

Your task: analyze the structured security alert below and return a SOC report.

STRICT OUTPUT RULES:
- Return ONLY a valid JSON object, no markdown, no preamble, no explanation.
- All text fields must be in FRENCH.
- Use exactly this structure:

{
  "summary": "2-3 sentences describing what happened and why it is dangerous",
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "attack_type": "precise attack category (e.g. SSH Brute Force, SQL Injection, Port Scan)",
  "mitre": "TXXXX.XXX – Technique Name",
  "recommendations": [
    "Immediate action 1 (blocking, isolation)",
    "Investigation action 2 (log review, forensics)",
    "Hardening action 3 (config, policy)"
  ],
  "iocs": [
    "indicator 1 (IP, port, pattern)",
    "indicator 2"
  ]
}
"""

_DEMO_ANALYSES = {
    "ssh brute force": {
        "summary": "Tentative de brute-force SSH détectée depuis une IP externe. Fréquence élevée de connexions infructueuses sur le port 22 en dehors des heures de bureau.",
        "risk_level": "HIGH",
        "attack_type": "SSH Brute Force",
        "mitre": "T1110.001 – Password Guessing",
        "recommendations": [
            "Bloquer l'IP source sur le pare-feu périphérique immédiatement.",
            "Vérifier les logs d'authentification SSH sur le serveur cible pour confirmer qu'aucun accès n'a abouti.",
            "Activer l'authentification par clé SSH et désactiver l'authentification par mot de passe."
        ],
        "iocs": ["IP source suspecte", "Port destination 22", "Fréquence > 100 req/min"]
    },
    "sql injection": {
        "summary": "Détection de requêtes HTTP contenant des caractères d'injection SQL ciblées vers le serveur d'applications. Risque d'exfiltration ou d'altération de la base de données.",
        "risk_level": "CRITICAL",
        "attack_type": "SQL Injection",
        "mitre": "T1190 – Exploit Public-Facing Application",
        "recommendations": [
            "Isoler temporairement le serveur web ou bloquer les requêtes suspectes via le WAF.",
            "Inspecter les requêtes de base de données exécutées pour confirmer s'il y a eu fuite de données.",
            "Appliquer des requêtes préparées (Prepared Statements) et assainir les entrées utilisateur dans le code de l'application."
        ],
        "iocs": ["Patterns SQL (UNION SELECT, OR 1=1)", "Port destination 80/443", "User-Agent suspect"]
    },
    "web scan": {
        "summary": "Balayage web automatisé (Scan de vulnérabilités) identifiant les répertoires et fichiers sensibles sur le serveur web.",
        "risk_level": "MEDIUM",
        "attack_type": "Web Directory Scanning",
        "mitre": "T1595.002 – Vulnerability Scanning",
        "recommendations": [
            "Bloquer temporairement l'IP du scanner sur le WAF / pare-feu.",
            "Analyser les codes de réponse HTTP (ex: 200 vs 404) pour identifier si des pages sensibles ont été découvertes.",
            "Désactiver le listing des répertoires et restreindre l'accès aux consoles d'administration."
        ],
        "iocs": ["IP source de scan", "Nombreux codes HTTP 404 en rafale", "Requêtes sur /admin, /config, etc."]
    },
    "default": {
        "summary": "Activité réseau anormale détectée par le module SOC AI. Analyse recommandée en raison d'une hausse significative de la fréquence des requêtes.",
        "risk_level": "MEDIUM",
        "attack_type": "Anomalous Network Activity",
        "mitre": "T1046 – Network Service Discovery",
        "recommendations": [
            "Examiner les flux réseau entre la source et la destination.",
            "Vérifier si l'activité correspond à un comportement légitime d'administration ou de supervision.",
            "Mettre en place une règle de limitation de débit (rate limiting) pour atténuer la fréquence."
        ],
        "iocs": ["Fréquence élevée d'événements", "Flux inhabituel"]
    }
}

def _build_user_prompt(alert: dict) -> str:
    """Construit le prompt utilisateur pour l'analyse d'alerte."""
    src_type = "EXTERNE (hors réseau)" if not alert.get("src_is_internal", 1) else "INTERNE"
    dst_type = "INTERNE" if alert.get("dst_is_internal", 1) else "EXTERNE"
    lateral  = "OUI — mouvement latéral possible" if alert.get("is_internal_to_internal") else "NON"
    
    return f"""
Analyze this Wazuh security alert:

[IDENTIFICATION]
- Nom de l'alerte  : {alert.get("alert_name", alert.get("description", "Inconnu"))}
- Sévérité Wazuh   : {alert.get("severity", "?")} (score {alert.get("severity_score", "?")})
- Timestamp        : {alert.get("timestamp", "?")}
- Contexte horaire : {alert.get("time_context", "?")}

[RÉSEAU]
- IP source        : {alert.get("src_ip", "?")} [{src_type}]
- Port source      : {alert.get("src_port", "?")}
- IP destination   : {alert.get("dst_ip", "?")} [{dst_type}]
- Port destination : {alert.get("dst_port", "?")} / service : {alert.get("dst_service", "?")}
- Protocole        : {alert.get("protocol", "?")}
- Même sous-réseau : {"OUI" if alert.get("same_subnet") else "NON"}
- Flux interne→int.: {lateral}

[COMPORTEMENT]
- Fréquence        : {alert.get("freq_per_min", "?")} événements/minute
- Haute fréquence  : {"OUI" if alert.get("is_high_freq") else "NON"}

[CLASSIFICATION XGBOOST]
- Prédiction       : {alert.get("prediction", "attack").upper()}
- Score de risque  : {alert.get("risk_score", "?")}%
- P(attack)        : {alert.get("proba_attack", "?")}
- P(false_positive): {alert.get("proba_fp", "?")}
- P(normal)        : {alert.get("proba_normal", "?")}

Provide the JSON SOC analysis now.
"""

def _parse_llm_json(raw: str) -> Optional[dict]:
    """Nettoie et parse le JSON renvoyé par le LLM."""
    text = raw.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
        
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    return None

def analyser_alerte(alert: dict, api_key: str = None) -> dict:
    """
    Analyse une alerte SOC via LLM (Groq ou Gemini) et retourne un dictionnaire structuré.
    Si aucune clé n'est fournie, utilise les démos pré-enregistrées.
    """
    effective_key = api_key or os.getenv("GROQ_API_KEY") or os.getenv("GEMINI_API_KEY")
    
    if not effective_key:
        # Fallback to local demo response matching the alert category
        alert_name = alert.get("alert_name", "").lower()
        for cat, data in _DEMO_ANALYSES.items():
            if cat in alert_name:
                return data
        return _DEMO_ANALYSES["default"]
        
    user_prompt = _build_user_prompt(alert)
    
    # Check if it looks like a Gemini key or Groq key
    # Groq keys usually start with 'gsk_'
    is_groq = effective_key.startswith("gsk_") or os.getenv("GROQ_API_KEY") is not None
    
    if is_groq:
        try:
            from groq import Groq
            client = Groq(api_key=effective_key)
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                temperature=0.1,
                max_tokens=800,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": user_prompt},
                ]
            )
            raw_content = response.choices[0].message.content
            parsed = _parse_llm_json(raw_content)
            if parsed:
                return parsed
        except Exception as e:
            print(f"  [WARN] Erreur API Groq : {e}. Tentative de bascule...")
            
    # Try Gemini fallback/direct if it's a Gemini key or if Groq failed
    try:
        import google.generativeai as genai
        genai.configure(api_key=effective_key)
        
        # Configure model
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction=SYSTEM_PROMPT
        )
        
        response = model.generate_content(
            user_prompt,
            generation_config={"temperature": 0.1}
        )
        
        raw_content = response.text
        parsed = _parse_llm_json(raw_content)
        if parsed:
            return parsed
            
    except Exception as e:
        print(f"  [ERROR] Erreur API Gemini / Groq : {e}. Utilisation du mode Démo.")
        
    # Local demo fallback if all API calls failed
    alert_name = alert.get("alert_name", "").lower()
    for cat, data in _DEMO_ANALYSES.items():
        if cat in alert_name:
            return data
    return _DEMO_ANALYSES["default"]
