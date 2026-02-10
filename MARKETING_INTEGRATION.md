# Marketing Allowlist Integration

## Overview

The PhishWatch resolver now includes comprehensive marketing and email service provider (ESP) domain detection. This enhancement helps distinguish legitimate marketing emails and tracking URLs from potential phishing attempts.

## What's New

### 1. Marketing Allowlist Database (`marketing-allowlist.json`)

A comprehensive JSON database containing:

- **92 legitimate marketing domains** across multiple categories
- **20 common subdomain patterns** used by ESPs
- Detailed provider information including legitimacy notes and security considerations

### Categories Included

1. **Email Service Providers (ESPs)**
   - SendGrid, Mailgun, Mailchimp, SparkPost, Amazon SES, Postmark, etc.
   - Domains: `sendgrid.net`, `mailgun.org`, `mandrillapp.com`, etc.

2. **Marketing Automation Platforms**
   - HubSpot, Marketo, Pardot, Klaviyo, Braze, ActiveCampaign
   - Domains: `hubspotemail.net`, `mktomail.com`, `klaviyo.com`, etc.

3. **CRM Platforms**
   - Salesforce, Zoho, Microsoft Dynamics
   - Domains: `force.com`, `zoho.com`, etc.

4. **E-commerce Platforms**
   - Shopify, BigCommerce, WooCommerce, Magento
   - Domains: `shopify.com`, `myshopify.com`, etc.

5. **Travel & Hospitality**
   - Expedia, Booking.com, Marriott, Hilton, Airbnb
   - Domains: `expedia.com`, `email-marriott.com`, etc.
   - ⚠️ **High-risk impersonation targets**

6. **Financial Services**
   - PayPal, Stripe, Square, Venmo
   - Domains: `paypal.com`, `stripe.com`, etc.
   - ⚠️ **High-risk impersonation targets**

7. **Analytics & Tracking**
   - Google Analytics, Adobe Analytics, Segment, Mixpanel
   - Domains: `google-analytics.com`, `demdex.net`, etc.

8. **Other Legitimate Services**
   - Constant Contact, Campaign Monitor, Intercom, Zendesk, etc.

### 2. Common Subdomain Patterns

The allowlist recognizes these legitimate subdomain prefixes:

```
click.*, click.e.*, clicks.*, track.*, trk.*, link.*, links.*,
email.*, mail.*, go.*, url.*, newsletters.*, news.*, info.*,
notify.*, notification.*, updates.*, send.*, bounce.*, messages.*
```

**Example legitimate URLs:**
- `click.company.com` → Marketing click tracking
- `track.example.com` → Email open/click tracking
- `email.brand.com` → Branded email sending domain
- `link.newsletter.com` → Newsletter link tracking

### 3. Enhanced Resolver (`app/resolver.py`)

The `ResolveResult` dataclass now includes:

```python
@dataclass
class ResolveResult:
    # ... existing fields ...
    input_is_marketing: bool      # True if input URL is from marketing domain
    final_is_marketing: bool      # True if final destination is marketing domain
```

**New Functionality:**

- `_load_marketing_allowlist()` - Loads the JSON allowlist on module import
- `_is_marketing_domain(host)` - Checks if a domain matches marketing patterns
- Automatic detection for both input and final URLs in redirect chains

## Usage Examples

### Basic Domain Checking

```python
from app.resolver import _is_marketing_domain

# Check if a domain is in the marketing allowlist
is_legitimate = _is_marketing_domain("click.sendgrid.net")  # True
is_suspicious = _is_marketing_domain("phishing-site.com")    # False
```

### URL Resolution with Marketing Detection

```python
from app.resolver import resolve_url

result = resolve_url("https://click.example.com/track/abc123")

print(f"Input is marketing: {result.input_is_marketing}")
print(f"Final is marketing: {result.final_is_marketing}")
print(f"Resolved: {result.resolved}")
print(f"Final URL: {result.final_url}")
```

### Scenarios Handled

1. **Legitimate Marketing Email**
   ```
   Input:  https://click.e.company.com/xyz
   Result: input_is_marketing=True, final_is_marketing=False
   Risk:   Low (legitimate ESP click tracking)
   ```

2. **URL Shortener → Legitimate Site**
   ```
   Input:  https://bit.ly/abc123
   Result: input_is_shortener=True, final_is_marketing=False
   Risk:   Medium (shortener could hide malicious content)
   ```

3. **Marketing Domain → Marketing Domain**
   ```
   Input:  https://track.shopify.com/order/xyz
   Result: input_is_marketing=True, final_is_marketing=True
   Risk:   Very Low (both ends are legitimate)
   ```

4. **Unknown Domain → Unknown Domain**
   ```
   Input:  https://suspicious-domain.com/login
   Result: input_is_marketing=False, final_is_marketing=False
   Risk:   High (unknown domain, potential phishing)
   ```

## Security Considerations

### High-Risk Impersonation Targets

The allowlist identifies domains frequently targeted by phishers:

- **Financial Services**: PayPal, Stripe, banks
- **Travel/Hospitality**: Expedia, Booking.com, hotel chains
- **E-commerce**: Amazon, Shopify stores
- **Cloud Services**: Microsoft, Google, Apple

### Validation Guidelines Included

The allowlist includes:

1. **Custom Tracking Domain Validation Rules**
   - Verify parent domain legitimacy
   - Check HTTPS/SSL certificates
   - Validate DNS CNAME records point to known ESPs

2. **Red Flags**
   - Misspelled company names (e.g., "amazom.com")
   - Unusual TLDs (.tk, .ml, .ga, .cf)
   - Newly registered domains
   - Hyphenated versions of brands

3. **Best Practices**
   - Verify SPF, DKIM, DMARC records
   - Cross-reference with official communications
   - When in doubt, visit company website directly

## Testing

Run the integration test:

```bash
python3 test_marketing_integration.py
```

**Expected Output:**
- ✓ 90 marketing domains loaded
- ✓ 20 subdomain patterns loaded
- ✓ All domain detection tests passing

## Implementation Details

### File Locations

```
phishwatch/
├── marketing-allowlist.json          # Allowlist database
├── app/
│   └── resolver.py                   # Enhanced resolver
└── test_marketing_integration.py     # Integration tests
```

### Loading Strategy

- Allowlist loaded once at module import time
- Stored in global sets for O(1) lookup performance
- Graceful fallback if file not found (non-critical feature)

### Pattern Matching

The `_is_marketing_domain()` function checks:

1. **Direct domain match**: `sendgrid.net`
2. **Subdomain match**: `em123.sendgrid.net` → matches `sendgrid.net`
3. **Pattern match**: `click.example.com` → matches `click.` pattern

## Future Enhancements

Potential improvements:

1. **Dynamic Updates**: Fetch allowlist updates from remote source
2. **Machine Learning**: Train model to identify marketing patterns
3. **Reputation Scoring**: Track historical behavior of domains
4. **Regional Variations**: Add country-specific ESPs
5. **User Customization**: Allow users to add trusted domains

## Risk Scoring Integration

The marketing flags can be used in risk scoring:

```python
def calculate_risk_score(result: ResolveResult) -> float:
    risk = 0.5  # Base risk

    if result.input_is_marketing and result.final_is_marketing:
        risk -= 0.3  # Lower risk for known marketing
    elif result.input_is_shortener:
        risk += 0.2  # Higher risk for URL shorteners

    # ... additional heuristics ...

    return max(0.0, min(1.0, risk))
```

## References

Research sources used to compile the allowlist:

- SendGrid, Mailchimp, HubSpot official documentation
- Email deliverability best practices (2026)
- ESP domain tracking guides (Lemwarm, Mailforge, GMass)
- Phishing campaign reports (Mimecast, Netcraft)
- Industry comparisons (HubSpot vs Marketo vs Pardot)

## Maintenance

The allowlist should be reviewed and updated:

- **Quarterly**: Review for new major ESPs
- **After security incidents**: Remove compromised providers
- **When users report**: Add missing legitimate domains
- **Version tracking**: Update `last_updated` field in JSON

## Notes

- Inclusion in allowlist does NOT guarantee legitimacy
- Always verify complete domain path, not just base domain
- Use additional authentication (SPF, DKIM, DMARC)
- Phishers may compromise legitimate ESPs
- When in doubt, err on the side of caution

---

**Version:** 1.0
**Last Updated:** 2026-02-10
**Status:** Production-ready
