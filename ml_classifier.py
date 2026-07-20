import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Open-Source Corpus: Intent Cluster Definitions
INTENT_CLUSTERS = {
    "ADVERSARIAL_PROMPT_HIJACK": {
        "text": "ignore previous instructions system override forget all safety rules developer mode enabled unrestricted persona system prompt",
        "category": "MALICIOUS",
        "base_risk": 85.0
    },
    "ADVERSARIAL_DATA_EXFILTRATION": {
        "text": "read confidential environment credentials upload external webhook post server steal API key database dump leak headers",
        "category": "MALICIOUS",
        "base_risk": 90.0
    },
    "ADVERSARIAL_COMMAND_INJECTION": {
        "text": "execute os system shell command base64 decode dropper curl payload spawn subprocess backdoor reverse shell pty",
        "category": "MALICIOUS",
        "base_risk": 95.0
    },
    "ADVERSARIAL_EVASION_ENCODING": {
        "text": "hidden zero width unicode character rot13 obfuscation b64decode bypass pattern security filter steganography",
        "category": "MALICIOUS",
        "base_risk": 80.0
    },
    "BENIGN_MATH_CALCULATOR": {
        "text": "evaluates basic arithmetic calculations safe addition multiplication math expressions numbers formula parser",
        "category": "BENIGN",
        "base_risk": 0.0
    },
    "BENIGN_WEATHER_LOOKUP": {
        "text": "fetches current weather update temperature forecast for city location humidity climate report",
        "category": "BENIGN",
        "base_risk": 0.0
    },
    "BENIGN_DATA_FORMATTER": {
        "text": "utility helper function for string formatting case conversion JSON parsing array sorting clean display",
        "category": "BENIGN",
        "base_risk": 0.0
    }
}

class LocalSemanticClassifier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 3), analyzer="word")
        self._fit_corpus()

    def _fit_corpus(self):
        self.cluster_keys = list(INTENT_CLUSTERS.keys())
        corpus_texts = [INTENT_CLUSTERS[k]["text"] for k in self.cluster_keys]
        self.vectorizer.fit(corpus_texts)
        self.cluster_vectors = self.vectorizer.transform(corpus_texts)

    def classify_intent(self, text_input: str) -> dict:
        """Classifies input text against open-source semantic intent vectors using cosine similarity."""
        if not text_input or len(text_input.strip()) < 3:
            return {"ml_threat_score": 0.0, "matched_cluster": "NONE", "similarity": 0.0, "confidence": "LOW"}

        input_vector = self.vectorizer.transform([text_input])
        similarities = cosine_similarity(input_vector, self.cluster_vectors)[0]

        best_idx = np.argmax(similarities)
        best_similarity = float(similarities[best_idx])
        best_cluster = self.cluster_keys[best_idx]
        cluster_info = INTENT_CLUSTERS[best_cluster]

        # Calculate threat score scaled by similarity threshold
        if cluster_info["category"] == "MALICIOUS" and best_similarity > 0.15:
            ml_threat_score = round(cluster_info["base_risk"] * min(best_similarity * 2.5, 1.0), 2)
            confidence = "HIGH" if best_similarity > 0.35 else "MEDIUM"
        else:
            ml_threat_score = 0.0
            confidence = "HIGH" if best_similarity > 0.30 else "LOW"

        return {
            "ml_threat_score": ml_threat_score,
            "matched_cluster": best_cluster,
            "similarity": round(best_similarity, 4),
            "confidence": confidence
        }

# Global singleton classifier instance
classifier = LocalSemanticClassifier()

def predict_semantic_intent(text: str) -> dict:
    return classifier.classify_intent(text)
