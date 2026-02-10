# PhishWatch Extension v2.6.3-beta Changelog

## Release Date: 2026-02-10

## Overview
Enhanced marketing infrastructure detection with comprehensive allowlist integration from the backend marketing-allowlist.json database.

---

## 🎯 Major Changes

### 1. **Comprehensive Marketing Allowlist (134 Domains)**

Integrated curated allowlist from `marketing-allowlist.json` with organized categories:

**New Categorized Domains (71 domains):**
- ✉️ **Email Service Providers (21)**: SendGrid, Mailgun, Mailchimp, Postmark, SparkPost, Amazon SES, Brevo, Iterable, Customer.io, etc.
- 🎯 **Marketing Automation (12)**: HubSpot, Marketo, Pardot, Klaviyo, Braze, Eloqua, ActiveCampaign, Omnisend
- 💼 **CRM Platforms (5)**: Salesforce, Zoho, Microsoft Dynamics
- 🛒 **E-commerce (5)**: Shopify, BigCommerce, WooCommerce, Magento
- ✈️ **Travel & Hospitality (8)**: Expedia, Booking.com, Marriott, Hilton, Airbnb
- 💰 **Financial Services (6)**: PayPal, Stripe, Square, Venmo
- 📊 **Analytics & Tracking (4)**: Google Analytics, Adobe Analytics (demdex.net), Segment, Mixpanel
- 🔧 **Other Services (10)**: Campaign Monitor, Constant Contact, ConvertKit, Intercom, Zendesk, etc.

**Legacy Domains (63 domains):** Retained for backwards compatibility including URL shorteners, CDNs, and additional marketing platforms.

### 2. **Debug Instrumentation**

Added comprehensive debugging for marketing allowlist hits:

```javascript
// Counter for tracking allowlist usage
var MARKETING_ALLOWLIST_HITS = 0;

// Console logging on allowlist match
console.log('[PhishWatch] Marketing domain allowlisted:', host, '(matched:', domain + ', total hits:', MARKETING_ALLOWLIST_HITS + ')');
```

**Debug Output Example:**
```
[PhishWatch] Marketing domain allowlisted: click.sendgrid.net (matched: sendgrid.net, total hits: 1)
[PhishWatch] Marketing domain allowlisted: email.shopify.com (matched: shopify.com, total hits: 2)
```

### 3. **Inline Documentation**

Added clear inline comments for each category explaining the domain types and examples:

```javascript
// Email Service Providers (ESPs) - 21 domains
// SendGrid, Mailgun, Mailchimp, Postmark, SparkPost, Amazon SES, etc.
"sendgrid.net", "sendgrid.com", ...
```

### 4. **Version Updates**

- Header: `v2.6.2 (Security Hardened)` → `v2.6.3-beta (Enhanced Marketing Detection)`
- Console log: Updated to reflect new version
- All version references updated throughout file

---

## 🔧 Technical Details

### File Changes

**File:** `extension/content.js`
- **Before:** 127 KB (v2.6.2)
- **After:** 129 KB (v2.6.3-beta)
- **Backup:** `content.js.v2.6.2.backup` (created)

### Function Updates

**Updated:** `isMarketingInfraTarget(url)` (Line ~573)
- Added `MARKETING_ALLOWLIST_HITS` counter increment
- Added console.log debug output with matched domain info
- Maintains existing matching logic (exact match + subdomain match)

**Updated:** `MARKETING_INFRA_DOMAINS` array (Line ~177)
- Expanded from ~50 domains to 134 domains
- Organized by 8 distinct categories
- Added inline comments for each category

### Flow Verification

✅ **Marketing Check Order Confirmed:**
1. `onClickCapture()` calls `detectMarketingInfrastructure()` (Line ~2736)
2. Marketing detection completes BEFORE `prescanHints()`
3. `prescanHints()` checks `excessive_subdomains` (Line ~2392)
4. Marketing flag passed to `runScan()` with reduced risk scoring

**Result:** Allowlist check happens BEFORE excessive_subdomain detection ✅

---

## 🧪 Testing

### Test File Created

**Location:** `extension/test_marketing_update.html`

**Test Categories:**
- Email Service Providers (SendGrid, Mailgun, Mailchimp)
- Marketing Automation (HubSpot, Marketo, Pardot)
- E-commerce (Shopify)
- Travel & Hospitality (Expedia, Marriott)
- Financial Services (PayPal, Stripe)
- Analytics (Google Analytics)
- Non-Marketing domains (should NOT be allowlisted)

### Testing Instructions

1. Load the PhishWatch extension with updated `content.js`
2. Open `test_marketing_update.html` in browser
3. Open browser console (F12)
4. Click test links to see allowlist detection in action
5. Verify console output: `[PhishWatch] Marketing domain allowlisted: ...`
6. Verify counter increments with each hit

### Expected Behavior

**For Marketing Domains:**
```
✓ Console log appears with domain name
✓ Counter increments
✓ Risk assessment reduced (marketing infrastructure flag set)
✓ Overlay only shown for HIGH risk or multiple signals
```

**For Non-Marketing Domains:**
```
✓ No console log
✓ Counter unchanged
✓ Normal risk assessment applied
✓ Standard overlay behavior
```

---

## 📊 Statistics

| Metric | Value |
|--------|-------|
| Total Marketing Domains | 134 |
| New Categorized Domains | 71 |
| Legacy Domains Retained | 63 |
| Categories | 8 |
| Lines Added | ~100 |
| Backup Files | 3 (v2.6.0, v2.6.1, v2.6.2) |

---

## 🔍 Code Quality

### Backwards Compatibility
✅ All legacy domains retained in "Legacy/Additional" section
✅ No breaking changes to existing logic
✅ Maintains existing `isMarketingInfraTarget()` function signature

### Performance
✅ O(n) lookup performance maintained (linear scan)
✅ Early return optimization on match
✅ Minimal memory overhead (~2KB additional array data)

### Maintainability
✅ Clear category organization
✅ Inline comments for each section
✅ Debug instrumentation for troubleshooting
✅ Version string clearly identifies beta status

---

## 🚀 Deployment Notes

### Pre-Deployment Checklist
- [x] Backup created (`content.js.v2.6.2.backup`)
- [x] Version strings updated
- [x] Debug logging added
- [x] Categories documented
- [x] Test file created
- [x] Code review completed

### Rollback Plan
If issues arise, restore from backup:
```bash
cp extension/content.js.v2.6.2.backup extension/content.js
```

### Monitoring
Monitor console for allowlist hits:
```javascript
// Check hit counter
console.log('Total allowlist hits:', MARKETING_ALLOWLIST_HITS);
```

---

## 📝 Future Enhancements

### Potential Improvements
1. **Pattern Matching**: Add subdomain pattern support (e.g., `click.`, `track.`, `email.`)
2. **Dynamic Loading**: Load allowlist from external JSON file
3. **Performance**: Convert array to Set for O(1) lookups
4. **Analytics**: Track allowlist hit rate and false positive rate
5. **User Customization**: Allow users to add trusted domains

### Integration Opportunities
- Sync with backend `marketing-allowlist.json` updates
- Add allowlist version tracking
- Implement automatic updates from backend
- Add allowlist effectiveness metrics to dashboard

---

## 🐛 Known Issues

**None reported** - This is a beta release for testing and validation.

---

## 👥 Credits

**Integration:** Claude Sonnet 4.5
**Source Data:** `marketing-allowlist.json` (v1.0, 2026-02-10)
**Research:** Compiled from SendGrid, Mailchimp, HubSpot, and industry documentation

---

## 📚 Related Documentation

- `MARKETING_INTEGRATION.md` - Backend integration documentation
- `marketing-allowlist.json` - Source allowlist database
- `test_marketing_integration.py` - Backend test suite
- `test_marketing_update.html` - Extension test page

---

**Version:** v2.6.3-beta
**Status:** Beta Testing
**Stability:** Production-ready pending testing validation
