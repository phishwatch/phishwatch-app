# PhishWatch V1 – API Specification

PhishWatch V1 exposes two primary endpoints:
1. POST /api/check
2. GET /api/recent-scans

All timestamps are ISO-8601 UTC. All responses are JSON.

---

## 1. POST /api/check

### Description
Analyze a URL and return a phishing risk score, verdict, indicators, and explanations.

### Request
- Method: POST
- Path: /api/check
- Content-Type: application/json

Example request body:

{
  "url": "https://example.com/login?email=test@example.com"
}

### Request Fields
- url (string, required): The URL to analyze. Must begin with http:// or https://.

---

### Successful Response (200 OK)

Example:

{
  "id": "cd8b8b2d-225f-4ac1-bbf2-7be410753e85",
  "url": "https://example.com/login?email=test@example.com",
  "verdict": "suspicious",
  "score": 62,
  "explanation": [
    "Contains credential-related keywords.",
    "Query string is unusually long or complex.",
    "Query contains sensitive parameters."
  ],
  "indicators": {
    "suspicious_tld": false,
    "ip_address_url": false,
    "many_subdomains": false,
    "punycode": false,
    "brand_lookalike": false,
    "url_shortener": false,
    "credential_keywords": true,
    "urgency_keywords": false,
    "long_query": true,
    "sensitive_query_params": true,
    "mismatched_brand": false
  },
  "external": {
    "gsb": { "checked": true, "status": "clean" },
    "virustotal": { "checked": false, "status": null }
  },
  "timestamp": "2025-11-20T12:34:56Z"
}

### Response Fields
- id (string): UUID for this scan.
- url (string): The analyzed URL.
- verdict (string): safe, suspicious, or malicious.
- score (integer): 0–100.
- explanation (array of strings): Human-readable explanations.
- timestamp (string): ISO-8601 UTC timestamp.

Indicators (boolean flags):
- suspicious_tld  
- ip_address_url  
- many_subdomains  
- punycode  
- brand_lookalike  
- url_shortener  
- credential_keywords  
- urgency_keywords  
- long_query  
- sensitive_query_params  
- mismatched_brand  

External reputation:
- gsb: { checked: bool, status: string or null }
- virustotal: { checked: bool, status: string or null }

---

### Error Responses

400 Bad Request:
{ "detail": "Invalid URL format" }

500 Internal Server Error:
{ "detail": "Internal server error" }

---

## 2. GET /api/recent-scans

### Description
Return recent scan results in reverse chronological order.

### Request
- Method: GET
- Path: /api/recent-scans
- Query parameters:
  - limit (integer, optional, default 20, max 100)

Example:
GET /api/recent-scans?limit=20

---

### Successful Response (200 OK)

Example:

{
  "items": [
    {
      "id": "cd8b8b2d-225f-4ac1-bbf2-7be410753e85",
      "url": "https://example.com/login",
      "verdict": "suspicious",
      "score": 62,
      "timestamp": "2025-11-20T12:34:56Z"
    },
    {
      "id": "33848018-6561-4a18-93ba-b932b9710a9c",
      "url": "https://google.com",
      "verdict": "safe",
      "score": 5,
      "timestamp": "2025-11-20T12:30:00Z"
    }
  ]
}

### Response Fields
Each item contains:
- id (string)
- url (string)
- verdict (string)
- score (integer)
- timestamp (string)

---

## Notes
- V1 has no authentication (development stage).
- Pagination and API keys may be added in future versions.

}
