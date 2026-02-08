# PhishWatch SSO-Safe Test Harness v2

## Setup Instructions

### 1. Add Test Helper to Your Extension

Copy the contents of `background-additions.js` into your existing `background.js` file, inside your message listener.

The code handles these test helper actions:
- `storage.getAll` - View all PhishWatch storage
- `storage.clear` - Clear all storage
- `storage.seedOrigins` - Seed expected origins for testing
- `storage.getOrigins` - Get learned origins for a page
- `storage.getBaseline` - View baseline data
- `storage.clearBaseline` - Clear baseline only

### 2. Reload Extension

Go to `chrome://extensions` and click the reload button on PhishWatch.

### 3. Start Test Server

```bash
cd sso-test-harness-v2
python3 -m http.server 8080
```

### 4. Open Test Harness

Navigate to `http://localhost:8080`

### 5. Open DevTools

- Press F12 to open DevTools
- Go to Console tab
- Filter by `[PhishWatch` to see only extension logs

## Test Categories

### Gate 1: Password-Only Triggers
Tests that Phase 4 novelty only arms for password fields, not OTP/seed.

### Gate 2: Form Action Mismatch
Tests that mismatch detection works correctly and exempts same-site/trusted auth.

### Gate 3: Expected Origins Learning
Tests the SSO-safe expected origins system:
- Learning from benign windows
- NOT learning from suspicious windows (guarded learning)
- Building the expected set correctly

### Novelty Correlation
Tests that signals only emit when BOTH novel AND treadmill indicator present.

### SSO Simulations
End-to-end tests simulating real SSO flows.

## Key Console Messages to Look For

| Test | Expected Console Output |
|------|------------------------|
| Password focus | `isPasswordTriggered: true` |
| OTP/Seed focus | `novelty: skipped (not password-triggered)` |
| Form mismatch | `form_action_origin_mismatch` |
| Trusted auth | `isTrustedAuth: true, isSuspicious: false` |
| Benign learning | `novelty: learning origins (benign window)` |
| Guarded (no learn) | `novelty: NOT learning origins (suspicious indicators)` |
| Novel + treadmill | `novel_runtime_sequence_observed` |
| Not novel | `novelty: not novel for this page (seen N times)` |
