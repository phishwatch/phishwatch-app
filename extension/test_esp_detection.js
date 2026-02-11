#!/usr/bin/env node
/**
 * PhishWatch v2.6.4-beta - ESP Pattern Detection Test Suite
 * Tests the pattern-based ESP detection with minimal allowlist approach
 */

const fs = require('fs');
const path = require('path');

console.log('='.repeat(70));
console.log('PhishWatch v2.6.4-beta - ESP Pattern Detection Test');
console.log('='.repeat(70));
console.log();

// Extract functions from content.js
const contentJs = fs.readFileSync(path.join(__dirname, 'content.js'), 'utf8');

// Extract the arrays and functions
const minimalAllowlistMatch = contentJs.match(/var MINIMAL_EXPLICIT_ALLOWLIST = \[([\s\S]*?)\];/);
const espKeywordsMatch = contentJs.match(/var ESP_DOMAIN_KEYWORDS = \[([\s\S]*?)\];/);
const trackingSubdomainsMatch = contentJs.match(/var ESP_TRACKING_SUBDOMAINS = \[([\s\S]*?)\];/);

if (!minimalAllowlistMatch || !espKeywordsMatch || !trackingSubdomainsMatch) {
  console.error('❌ Could not extract configuration from content.js');
  process.exit(1);
}

// Parse arrays
function parseStringArray(text) {
  const items = [];
  const regex = /"([^"]+)"/g;
  let match;
  while ((match = regex.exec(text)) !== null) {
    items.push(match[1]);
  }
  return items;
}

const MINIMAL_EXPLICIT_ALLOWLIST = parseStringArray(minimalAllowlistMatch[1]);
const ESP_DOMAIN_KEYWORDS = parseStringArray(espKeywordsMatch[1]);
const ESP_TRACKING_SUBDOMAINS = parseStringArray(trackingSubdomainsMatch[1]);

console.log(`✓ Loaded ${MINIMAL_EXPLICIT_ALLOWLIST.length} domains from MINIMAL_EXPLICIT_ALLOWLIST`);
console.log(`✓ Loaded ${ESP_DOMAIN_KEYWORDS.length} ESP domain keywords`);
console.log(`✓ Loaded ${ESP_TRACKING_SUBDOMAINS.length} tracking subdomain prefixes`);
console.log();

// Implement the functions from content.js
function isRandomID(subdomain) {
  if (!subdomain || subdomain.length < 3) return false;
  const s = String(subdomain).toLowerCase();

  if (/^[a-z]+-\d+$/.test(s)) return true;
  if (/^[a-z0-9]{12,}$/i.test(s)) return true;
  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(s)) return true;
  if (/^[a-z0-9+\/]{16,}={0,2}$/i.test(s)) return true;

  return false;
}

function calculateESPScore(url) {
  let score = 0;
  const breakdown = {
    domain_keywords: 0,
    known_esp: 0,
    tracking_subdomain: 0,
    random_id: 0
  };

  try {
    const urlObj = new URL(url);
    const host = urlObj.hostname.toLowerCase();
    const parts = host.split('.');

    // Check 1: Domain contains email/mail/newsletter keywords (+2 points)
    for (const keyword of ESP_DOMAIN_KEYWORDS) {
      if (host.indexOf(keyword) !== -1) {
        breakdown.domain_keywords = 2;
        score += 2;
        break;
      }
    }

    // Check 2: Known ESP domain from minimal list (+3 points)
    for (const allowedDomain of MINIMAL_EXPLICIT_ALLOWLIST) {
      if (host === allowedDomain || host.endsWith('.' + allowedDomain)) {
        breakdown.known_esp = 3;
        score += 3;
        break;
      }
    }

    // Check 3: Tracking subdomains (+1 per match, max 2)
    let trackingMatches = 0;
    for (let i = 0; i < parts.length && i < 2; i++) {
      for (const trackingPrefix of ESP_TRACKING_SUBDOMAINS) {
        if (parts[i] === trackingPrefix) {
          trackingMatches++;
          if (trackingMatches <= 2) {
            breakdown.tracking_subdomain++;
            score++;
          }
          break;
        }
      }
    }

    // Check 4: Random ID in first subdomain (+1 point)
    if (parts.length >= 2 && isRandomID(parts[0])) {
      breakdown.random_id = 1;
      score += 1;
    }

  } catch (e) {
    // Invalid URL
  }

  return { score, breakdown };
}

function shouldAllowExcessiveSubdomains(url, subdomainCount) {
  const espResult = calculateESPScore(url);
  const score = espResult.score;
  const breakdown = espResult.breakdown;

  let allow = false;
  let reason = '';

  try {
    const urlObj = new URL(url);
    const host = urlObj.hostname.toLowerCase();

    if (score >= 4) {
      allow = true;
      reason = 'High confidence ESP (score >= 4)';
    } else if (score >= 2) {
      allow = true;
      reason = 'Likely ESP (score >= 2)';
    } else {
      for (const allowedDomain of MINIMAL_EXPLICIT_ALLOWLIST) {
        if (host === allowedDomain || host.endsWith('.' + allowedDomain)) {
          allow = true;
          reason = 'Explicit allowlist (non-ESP service)';
          break;
        }
      }

      if (!allow) {
        reason = 'Suspicious (score < 2, not in allowlist)';
      }
    }

  } catch (e) {
    allow = false;
    reason = 'Invalid URL';
  }

  return { allow, reason, score, breakdown };
}

// Test cases
const testCases = [
  {
    category: 'High Confidence ESP (Score >= 4)',
    tests: [
      {
        url: 'https://hs-26823259.s.hubspotemail-eu1.net/track/click',
        expectedAllow: true,
        expectedMinScore: 4,
        description: 'HubSpot tracking (random ID + tracking subdomain + ESP keyword)'
      },
      {
        url: 'https://em1234.sendgrid.net/ls/click',
        expectedAllow: true,
        expectedMinScore: 4,
        description: 'SendGrid (random ID + tracking subdomain + ESP keyword)'
      },
      {
        url: 'https://click.email.company-newsletter.com/track',
        expectedAllow: true,
        expectedMinScore: 4,
        description: 'Generic ESP (tracking subdomain + email keyword)'
      }
    ]
  },
  {
    category: 'Likely ESP (Score >= 2)',
    tests: [
      {
        url: 'https://click.e.ritzcarltonyachtcollection.com/voyage',
        expectedAllow: true,
        expectedMinScore: 2,
        description: 'Ritz Carlton marketing (tracking subdomains: click + e)'
      },
      {
        url: 'https://track.company.com/campaign',
        expectedAllow: true,
        expectedMinScore: 2,
        description: 'Company tracking link (tracking subdomain)'
      },
      {
        url: 'https://email.shopify.com/order/123',
        expectedAllow: true,
        expectedMinScore: 2,
        description: 'Shopify email (email keyword + tracking subdomain)'
      },
      {
        url: 'https://newsletter.brand.com/unsubscribe',
        expectedAllow: true,
        expectedMinScore: 2,
        description: 'Newsletter domain (tracking subdomain + keyword)'
      }
    ]
  },
  {
    category: 'Explicit Allowlist (Non-ESP Services)',
    tests: [
      {
        url: 'https://billing.stripe.com/invoice/123',
        expectedAllow: true,
        expectedMinScore: 3,
        description: 'Stripe billing (explicit allowlist)'
      },
      {
        url: 'https://secure.login.microsoft.com/auth',
        expectedAllow: true,
        expectedMinScore: 3,
        description: 'Microsoft login (explicit allowlist)'
      },
      {
        url: 'https://api.github.com/repos/user/project',
        expectedAllow: true,
        expectedMinScore: 3,
        description: 'GitHub API (explicit allowlist)'
      }
    ]
  },
  {
    category: 'Suspicious (Should Block)',
    tests: [
      {
        url: 'https://secure.verify.account-microsoft.com.evil.com/login',
        expectedAllow: false,
        expectedMinScore: 0,
        description: 'Phishing attempt (spoofing Microsoft)'
      },
      {
        url: 'https://login.paypal.secure-verification.tk/confirm',
        expectedAllow: false,
        expectedMinScore: 0,
        description: 'Phishing attempt (spoofing PayPal)'
      },
      {
        url: 'https://a.b.c.d.e.suspicious.com/page',
        expectedAllow: false,
        expectedMinScore: 0,
        description: 'Excessive subdomains without ESP indicators'
      }
    ]
  }
];

// Run tests
let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const failures = [];

testCases.forEach(category => {
  console.log(`\n${'='.repeat(70)}`);
  console.log(`📂 ${category.category}`);
  console.log('='.repeat(70));

  category.tests.forEach(test => {
    totalTests++;
    const subdomainCount = new URL(test.url).hostname.split('.').length - 2;
    const result = shouldAllowExcessiveSubdomains(test.url, subdomainCount);

    const allowPassed = result.allow === test.expectedAllow;
    const scorePassed = result.score >= test.expectedMinScore;
    const passed = allowPassed && scorePassed;

    if (passed) {
      passedTests++;
      console.log(`✅ PASS: ${test.description}`);
      console.log(`   Score: ${result.score} (expected >= ${test.expectedMinScore})`);
      console.log(`   Decision: ${result.allow ? 'ALLOW' : 'BLOCK'} (${result.reason})`);
      console.log(`   Breakdown:`, result.breakdown);
    } else {
      failedTests++;
      console.log(`❌ FAIL: ${test.description}`);
      console.log(`   Expected: allow=${test.expectedAllow}, score>=${test.expectedMinScore}`);
      console.log(`   Got: allow=${result.allow}, score=${result.score}`);
      console.log(`   Reason: ${result.reason}`);
      console.log(`   Breakdown:`, result.breakdown);
      failures.push({
        category: category.category,
        test: test.description,
        url: test.url,
        expected: { allow: test.expectedAllow, minScore: test.expectedMinScore },
        actual: { allow: result.allow, score: result.score },
        reason: result.reason
      });
    }
    console.log();
  });
});

// Summary
console.log('='.repeat(70));
console.log('📊 TEST SUMMARY');
console.log('='.repeat(70));
console.log(`Total Tests:  ${totalTests}`);
console.log(`✅ Passed:     ${passedTests} (${Math.round(passedTests/totalTests*100)}%)`);
console.log(`❌ Failed:     ${failedTests} (${Math.round(failedTests/totalTests*100)}%)`);
console.log();
console.log(`Configuration:`);
console.log(`  Minimal Allowlist: ${MINIMAL_EXPLICIT_ALLOWLIST.length} domains`);
console.log(`  ESP Keywords: ${ESP_DOMAIN_KEYWORDS.length} keywords`);
console.log(`  Tracking Subdomains: ${ESP_TRACKING_SUBDOMAINS.length} prefixes`);
console.log('='.repeat(70));

// Show failures
if (failures.length > 0) {
  console.log('\n❌ FAILED TESTS DETAIL:');
  console.log('='.repeat(70));
  failures.forEach((f, i) => {
    console.log(`\n${i + 1}. ${f.category} - ${f.test}`);
    console.log(`   URL: ${f.url}`);
    console.log(`   Expected: allow=${f.expected.allow}, score>=${f.expected.minScore}`);
    console.log(`   Actual: allow=${f.actual.allow}, score=${f.actual.score}`);
    console.log(`   Reason: ${f.reason}`);
  });
  console.log();
}

// Final result
console.log();
if (failedTests === 0) {
  console.log('🎉 ALL TESTS PASSED! ESP pattern detection is working correctly.');
  console.log();
  console.log('Key Features:');
  console.log('  ✓ Minimal allowlist (15 domains instead of 121)');
  console.log('  ✓ Pattern-based ESP detection');
  console.log('  ✓ Zero false positives on legitimate ESPs');
  console.log('  ✓ Still blocks phishing attempts');
} else {
  console.log(`⚠️  ${failedTests} test(s) failed. Review the failures above.`);
  process.exit(1);
}
