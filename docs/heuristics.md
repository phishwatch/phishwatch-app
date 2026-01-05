# PhishWatch V1 – Heuristics & Scoring

PhishWatch V1 uses deterministic URL-based heuristics plus optional reputation lookups to compute a score (0–100) and assign a verdict:

- 0–39 → safe  
- 40–69 → suspicious  
- 70–100 → malicious  

Each heuristic adds points and a short explanation.

---

## Heuristics Overview (H1–H14)

### H1 – Suspicious TLD  
Applies when the top-level domain is in a high-abuse list (for example: .xyz, .top, .click, .link, .info).  
Score: +20

### H2 – IP Address URL  
Triggered when the host portion of the URL is an IPv4 or IPv6 address.  
Score: +40

### H3 – Many Subdomains  
Applies when the domain has 4 or more labels (subdomain levels) and is not in a small allowlist of known cloud providers.  
Score: +10

### H4 – Punycode / Unicode  
Triggered when the domain contains "xn--" or non-ASCII characters (Unicode).  
Score: +30

### H5 – Brand Lookalike  
Applies when the domain closely resembles a well-known brand (string similarity or brand name plus extra words).  
Score: +35

### H6 – URL Shortener  
Applies when the domain is a known shortener (such as bit.ly, t.co, tinyurl.com, ow.ly, etc.).  
Score: +25

### H7 – Credential Keywords  
Triggered when the path contains login-related terms such as: login, signin, account, verify, reset, password, secure.  
Score: +20

### H8 – Urgency Keywords  
Triggered when the path contains terms such as: urgent, important, warning, suspend, locked.  
Score: +10

### H9 – Long Query String  
Triggered when the query string is longer than 80 characters or contains 6 or more parameters.  
Score: +10

### H10 – Sensitive Query Parameters  
Triggered when the query contains keys such as: email, user, token, session, password, account.  
Score: +20

### H11 – Brand Mismatch  
Triggered when the path or subdomain references a known brand name but the main domain does not match that brand.  
Score: +20

### H12 – Google Safe Browsing (Malicious)  
Triggered when Google Safe Browsing marks the URL or domain as malicious.  
Score rule: set score = max(score, 90)

### H13 – Google Safe Browsing (Suspicious)  
Triggered when Google Safe Browsing returns a warning or "uncommon" result.  
Score: +40

### H14 – VirusTotal Positives  
Triggered when VirusTotal reports one or more detections for the URL or domain.  
Score rule: set score = max(score, 90)

---

## Explanation Strings

Each heuristic adds a short explanation when it triggers:

- H1: TLD is commonly used in phishing or spam campaigns.  
- H2: URL uses an IP address instead of a domain name.  
- H3: Domain has unusually many nested subdomains.  
- H4: Domain uses Unicode or punycode (possible lookalike domain).  
- H5: Domain resembles a known brand (possible impersonation).  
- H6: URL uses a shortening service (destination is hidden).  
- H7: Path contains credential-related keywords.  
- H8: Path contains urgency or pressure language.  
- H9: Query string is unusually long or complex.  
- H10: Query contains sensitive parameters.  
- H11: Brand name appears, but the main domain does not match that brand.  
- H12: Google Safe Browsing reports this URL or domain as malicious.  
- H13: Google Safe Browsing reports this URL or domain as suspicious or uncommon.  
- H14: VirusTotal engines report detections for this URL or domain.

---

## Scoring Algorithm

1. Start with:  
   - score = 0  
   - explanation = empty list  
   - indicators = map from heuristic name to false

2. For each heuristic that triggers:  
   - Add its score to the total score.  
   - Append its explanation string to the explanation list.  
   - Mark the corresponding indicator as true.

3. Apply special rules:  
   - If H12 (GSB malicious) triggers, set score = max(score, 90).  
   - If H14 (VirusTotal positives) triggers, set score = max(score, 90).  
   - If no reputation data is available, score is at least 50, and at least 3 heuristics triggered, add an extra +10 to the score (but do not exceed 100).

4. Cap the final score at 100.

5. Map the final score to a verdict:  
   - 0–39  → safe  
   - 40–69 → suspicious  
   - 70–100 → malicious  

---

## Notes

- V1 uses deterministic rule-based logic only (no machine learning).  
- Explanations should be short and understandable for non-technical users.  
- Reputation checks (Google Safe Browsing and VirusTotal) are optional and depend on API keys being configured.  
