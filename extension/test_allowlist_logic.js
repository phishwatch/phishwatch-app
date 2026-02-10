#!/usr/bin/env node
/**
 * PhishWatch v2.6.3-beta Marketing Allowlist Logic Test
 * Tests the domain matching logic without requiring actual URLs to exist
 */

// Extract the MARKETING_INFRA_DOMAINS array from content.js
const fs = require('fs');
const path = require('path');

console.log('='.repeat(70));
console.log('PhishWatch v2.6.3-beta - Marketing Allowlist Logic Test');
console.log('='.repeat(70));
console.log();

// Read content.js and extract MARKETING_INFRA_DOMAINS
const contentJs = fs.readFileSync(path.join(__dirname, 'content.js'), 'utf8');

// Extract the domains array using regex
const domainsMatch = contentJs.match(/var MARKETING_INFRA_DOMAINS = \[([\s\S]*?)\];/);
if (!domainsMatch) {
  console.error('❌ Could not extract MARKETING_INFRA_DOMAINS from content.js');
  process.exit(1);
}

// Parse domains from the array
const domainsText = domainsMatch[1];
const domains = [];
const domainRegex = /"([^"]+)"/g;
let match;
while ((match = domainRegex.exec(domainsText)) !== null) {
  domains.push(match[1]);
}

console.log(`✓ Extracted ${domains.length} domains from MARKETING_INFRA_DOMAINS`);
console.log();

// Replicate the isMarketingInfraTarget logic
function isMarketingInfraTarget(url) {
  try {
    const urlObj = new URL(url);
    const host = urlObj.hostname.toLowerCase();

    for (const domain of domains) {
      const d = domain.toLowerCase();
      if (host === d || host.endsWith('.' + d)) {
        return { match: true, domain: d, host: host };
      }
    }
    return { match: false, host: host };
  } catch (e) {
    return { match: false, error: e.message };
  }
}

// Test cases organized by category
const testCases = [
  {
    category: 'Email Service Providers (ESPs)',
    tests: [
      { url: 'https://sendgrid.net/test', expected: true, desc: 'SendGrid root domain' },
      { url: 'https://click.sendgrid.net/track/123', expected: true, desc: 'SendGrid subdomain' },
      { url: 'https://em123.sendgrid.net/campaign', expected: true, desc: 'SendGrid multi-level subdomain' },
      { url: 'https://mailgun.org/api', expected: true, desc: 'Mailgun root' },
      { url: 'https://track.mailgun.org/click', expected: true, desc: 'Mailgun subdomain' },
      { url: 'https://mailchimp.com/campaigns', expected: true, desc: 'Mailchimp root' },
      { url: 'https://list-manage.com/track', expected: true, desc: 'Mailchimp list-manage' },
      { url: 'https://mandrillapp.com/send', expected: true, desc: 'Mandrill' },
      { url: 'https://postmarkapp.com/email', expected: true, desc: 'Postmark' },
      { url: 'https://amazonses.com/bounce', expected: true, desc: 'Amazon SES' },
    ]
  },
  {
    category: 'Marketing Automation',
    tests: [
      { url: 'https://hubspot.com/marketing', expected: true, desc: 'HubSpot root' },
      { url: 'https://click.hs-sites.com/track', expected: true, desc: 'HubSpot sites subdomain' },
      { url: 'https://email.hubspotemail.net/campaign', expected: true, desc: 'HubSpot email subdomain' },
      { url: 'https://marketo.com/lead', expected: true, desc: 'Marketo root' },
      { url: 'https://click.mktomail.com/track', expected: true, desc: 'Marketo mail subdomain' },
      { url: 'https://pardot.com/email', expected: true, desc: 'Pardot root' },
      { url: 'https://go.pardot.com/track', expected: true, desc: 'Pardot go subdomain' },
      { url: 'https://klaviyo.com/campaign', expected: true, desc: 'Klaviyo' },
      { url: 'https://braze.com/push', expected: true, desc: 'Braze' },
    ]
  },
  {
    category: 'CRM Platforms',
    tests: [
      { url: 'https://salesforce.com/crm', expected: true, desc: 'Salesforce root' },
      { url: 'https://login.salesforce.com/auth', expected: true, desc: 'Salesforce login subdomain' },
      { url: 'https://force.com/api', expected: true, desc: 'Force.com' },
      { url: 'https://zoho.com/crm', expected: true, desc: 'Zoho root' },
      { url: 'https://mail.zoho.com/send', expected: true, desc: 'Zoho mail subdomain' },
    ]
  },
  {
    category: 'E-commerce Platforms',
    tests: [
      { url: 'https://shopify.com/admin', expected: true, desc: 'Shopify root' },
      { url: 'https://mystore.myshopify.com/products', expected: true, desc: 'Shopify store subdomain' },
      { url: 'https://email.shopify.com/order', expected: true, desc: 'Shopify email subdomain' },
      { url: 'https://bigcommerce.com/store', expected: true, desc: 'BigCommerce' },
      { url: 'https://woocommerce.com/shop', expected: true, desc: 'WooCommerce' },
    ]
  },
  {
    category: 'Travel & Hospitality',
    tests: [
      { url: 'https://expedia.com/hotels', expected: true, desc: 'Expedia root' },
      { url: 'https://email.expedia.com/booking', expected: true, desc: 'Expedia email subdomain' },
      { url: 'https://expediamail.com/confirmation', expected: true, desc: 'Expedia mail domain' },
      { url: 'https://booking.com/hotel', expected: true, desc: 'Booking.com' },
      { url: 'https://marriott.com/reservation', expected: true, desc: 'Marriott root' },
      { url: 'https://email-marriott.com/confirmation', expected: true, desc: 'Marriott email domain' },
      { url: 'https://hilton.com/booking', expected: true, desc: 'Hilton' },
      { url: 'https://airbnb.com/rooms', expected: true, desc: 'Airbnb' },
    ]
  },
  {
    category: 'Financial Services',
    tests: [
      { url: 'https://paypal.com/checkout', expected: true, desc: 'PayPal root' },
      { url: 'https://email.paypal.com/receipt', expected: true, desc: 'PayPal email subdomain' },
      { url: 'https://stripe.com/payments', expected: true, desc: 'Stripe root' },
      { url: 'https://email.stripe.com/invoice', expected: true, desc: 'Stripe email subdomain' },
      { url: 'https://square.com/pos', expected: true, desc: 'Square' },
      { url: 'https://venmo.com/payment', expected: true, desc: 'Venmo' },
    ]
  },
  {
    category: 'Analytics & Tracking',
    tests: [
      { url: 'https://google-analytics.com/collect', expected: true, desc: 'Google Analytics' },
      { url: 'https://track.google-analytics.com/event', expected: true, desc: 'Google Analytics subdomain' },
      { url: 'https://demdex.net/id', expected: true, desc: 'Adobe Analytics (demdex)' },
      { url: 'https://segment.com/track', expected: true, desc: 'Segment' },
      { url: 'https://mixpanel.com/track', expected: true, desc: 'Mixpanel' },
    ]
  },
  {
    category: 'Other Legitimate Services',
    tests: [
      { url: 'https://constantcontact.com/campaign', expected: true, desc: 'Constant Contact' },
      { url: 'https://createsend.com/track', expected: true, desc: 'Campaign Monitor' },
      { url: 'https://convertkit.com/email', expected: true, desc: 'ConvertKit' },
      { url: 'https://intercom.com/chat', expected: true, desc: 'Intercom' },
      { url: 'https://zendesk.com/ticket', expected: true, desc: 'Zendesk' },
    ]
  },
  {
    category: 'Non-Marketing Domains (Should NOT Match)',
    tests: [
      { url: 'https://suspicious-site.com/login', expected: false, desc: 'Suspicious domain' },
      { url: 'https://phishing.test/credentials', expected: false, desc: 'Phishing test domain' },
      { url: 'https://example.com/page', expected: false, desc: 'Generic example domain' },
      { url: 'https://evil-sendgrid.net/fake', expected: false, desc: 'Fake SendGrid lookalike' },
      { url: 'https://sendgrid.net.evil.com/phish', expected: false, desc: 'Subdomain spoofing attempt' },
      { url: 'https://notinallowlist.com/test', expected: false, desc: 'Random domain' },
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
    const result = isMarketingInfraTarget(test.url);
    const passed = result.match === test.expected;

    if (passed) {
      passedTests++;
      const matchInfo = result.match ? `✓ matched: ${result.domain}` : '✓ no match';
      console.log(`✅ PASS: ${test.desc.padEnd(40)} ${matchInfo}`);
    } else {
      failedTests++;
      const matchInfo = result.match ? `matched: ${result.domain}` : 'no match';
      console.log(`❌ FAIL: ${test.desc.padEnd(40)} ${matchInfo} (expected: ${test.expected ? 'match' : 'no match'})`);
      failures.push({
        category: category.category,
        test: test.desc,
        url: test.url,
        expected: test.expected,
        actual: result.match,
        matchedDomain: result.domain
      });
    }
  });
});

// Summary
console.log('\n' + '='.repeat(70));
console.log('📊 TEST SUMMARY');
console.log('='.repeat(70));
console.log(`Total Tests:  ${totalTests}`);
console.log(`✅ Passed:     ${passedTests} (${Math.round(passedTests/totalTests*100)}%)`);
console.log(`❌ Failed:     ${failedTests} (${Math.round(failedTests/totalTests*100)}%)`);
console.log(`📋 Domains:    ${domains.length}`);
console.log('='.repeat(70));

// Show failures in detail
if (failures.length > 0) {
  console.log('\n❌ FAILED TESTS DETAIL:');
  console.log('='.repeat(70));
  failures.forEach((f, i) => {
    console.log(`\n${i + 1}. ${f.category} - ${f.test}`);
    console.log(`   URL: ${f.url}`);
    console.log(`   Expected: ${f.expected ? 'MATCH' : 'NO MATCH'}`);
    console.log(`   Actual: ${f.actual ? 'MATCH' : 'NO MATCH'}`);
    if (f.matchedDomain) {
      console.log(`   Matched Domain: ${f.matchedDomain}`);
    }
  });
  console.log();
}

// Final result
console.log();
if (failedTests === 0) {
  console.log('🎉 ALL TESTS PASSED! Marketing allowlist is working correctly.');
} else {
  console.log(`⚠️  ${failedTests} test(s) failed. Review the failures above.`);
  process.exit(1);
}
