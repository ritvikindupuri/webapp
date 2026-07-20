import re
import unicodedata
from ml_classifier import predict_semantic_intent

INJECTION_PATTERNS = [
    (re.compile(r'\bignore\s+previous\s+instructions\b', re.IGNORECASE), "System Instruction Override"),
    (re.compile(r'\bsystem\s*:\s*override\b', re.IGNORECASE), "System Override Delimiter"),
    (re.compile(r'\byou\s+are\s+now\s+(?:an?\s+)?unrestricted\b', re.IGNORECASE), "Jailbreak Persona Injection"),
    (re.compile(r'\bforget\s+all\s+(?:safety\s+)?rules\b', re.IGNORECASE), "Safety Boundary Erasure"),
    (re.compile(r'</?system(?:_prompt)?>', re.IGNORECASE), "System Tag XML Escape"),
    (re.compile(r'<\|(?:im_start|im_end|endoftext)\|>', re.IGNORECASE), "Special Token Context Escape"),
    (re.compile(r'```system', re.IGNORECASE), "Markdown Context Hijack"),
    (re.compile(r'\bdeveloper\s+mode\s+enabled\b', re.IGNORECASE), "Developer Mode Jailbreak")
]

def scan_and_sanitize_prompt_injection(text: str) -> dict:
    """Performs Layer 2 indirect prompt injection detection and local ML semantic intent classification."""
    if not text:
        return {"risk_score": 0.0, "triggers": [], "sanitized_text": "", "ml_result": {}}

    triggers = []
    risk_score = 0.0
    sanitized_text = text

    # 1. Regex Pattern Injection Scanner
    for pattern, label in INJECTION_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            risk_score += 35.0
            triggers.append({
                "vector": label,
                "count": len(matches),
                "matched_sample": matches[0][:40]
            })
            sanitized_text = pattern.sub("[REDACTED_PROMPT_INJECTION]", sanitized_text)

    # 2. Local Open-Source ML Semantic Intent Classifier
    ml_result = predict_semantic_intent(text)
    if ml_result["ml_threat_score"] > 0:
        risk_score = max(risk_score, ml_result["ml_threat_score"])
        triggers.append({
            "vector": f"Open-Source ML Semantic Intent ({ml_result['matched_cluster']})",
            "count": 1,
            "matched_sample": f"Cosine Sim: {ml_result['similarity']} (Conf: {ml_result['confidence']})"
        })

    normalized_text = unicodedata.normalize("NFKD", sanitized_text)

    return {
        "risk_score": min(risk_score, 100.0),
        "triggers": triggers,
        "sanitized_text": normalized_text,
        "ml_result": ml_result
    }
