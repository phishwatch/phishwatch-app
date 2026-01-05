# PhishWatch V1 – Data Model & Storage

PhishWatch V1 uses a single main entity: ScanResult.  
Storage for the MVP is SQLite (a single database file, for example: phishwatch.db).

---

## ScanResult – Application-Level Schema

Fields (conceptual model, as used in the API and code):

- id (string, UUID)
- url (string)
- verdict (string: "safe", "suspicious", or "malicious")
- score (integer, 0–100)
- explanation (array of strings)
- indicators (map from string to boolean)
- external (object with optional reputation info)
  - gsb: { checked: bool, status: string or null }
  - virustotal: { checked: bool, status: string or null }
- created_at (string, ISO-8601 UTC timestamp)

This schema corresponds to the JSON structure returned by the API.

---

## Database Storage (SQLite)

For the MVP, ScanResult records are stored in a single table named "scans".

Suggested columns:

- id              TEXT PRIMARY KEY
- url             TEXT NOT NULL
- verdict         TEXT NOT NULL
- score           INTEGER NOT NULL
- explanation_json TEXT NOT NULL      (JSON-encoded array of strings)
- indicators_json  TEXT NOT NULL      (JSON-encoded object: map<string, bool>)
- external_json    TEXT               (JSON-encoded object with GSB/VT info, nullable)
- created_at       TEXT NOT NULL      (ISO-8601 UTC timestamp string)

---

## Example Schema (SQLite)

This is an example of how the table could be created:

- Table: scans
- Columns:
  - id: TEXT, primary key
  - url: TEXT, not null
  - verdict: TEXT, not null
  - score: INTEGER, not null
  - explanation_json: TEXT, not null
  - indicators_json: TEXT, not null
  - external_json: TEXT, nullable
  - created_at: TEXT, not null

Index:

- Index on created_at for efficient retrieval of recent scans:
  - name: idx_scans_created_at
  - definition: index on scans(created_at DESC)

---

## Usage Patterns

- When a new URL is scanned:
  - Generate a UUID for id.
  - Compute verdict, score, explanation list, indicators map, and external object.
  - Serialize explanation, indicators, and external as JSON strings.
  - Insert one row into the scans table.

- For GET /api/recent-scans:
  - Query scans ordered by created_at descending.
  - Apply a limit (for example, 20 by default).
  - Deserialize the JSON fields into the API response objects.

---

## Notes

- SQLite is sufficient for the MVP and easy to deploy in a single container.  
- The schema is intentionally simple and can be migrated later to PostgreSQL or another database if needed.  
- JSON fields provide flexibility for indicators and external reputation data without complex relational modeling.  
