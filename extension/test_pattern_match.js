#!/usr/bin/env node

const url = 'https://click.e.ritzcarltonyachtcollection.com/?qs=eyJkZ...';
const urlObj = new URL(url);
const host = urlObj.hostname.toLowerCase();

console.log('='.repeat(70));
console.log('Testing Subdomain Pattern Matching');
console.log('='.repeat(70));
console.log('URL:', url.substring(0, 60) + '...');
console.log('Host:', host);
console.log('Parts:', host.split('.').join(' > '));
console.log('Part count:', host.split('.').length);
console.log('');

const patterns = [
  'click.', 'click.e.', 'clicks.', 'track.', 'trk.', 'link.', 'links.',
  'email.', 'go.', 'url.', 'mail.'
];

console.log('Testing patterns:');
console.log('-'.repeat(70));

let matched = false;
patterns.forEach(pattern => {
  const startsWithPattern = host.startsWith(pattern);
  const containsPattern = host.indexOf('.' + pattern) !== -1;
  const parts = host.split('.');
  const hasEnoughParts = parts.length >= 3;

  if ((startsWithPattern || containsPattern) && hasEnoughParts) {
    console.log('✅ MATCH FOUND!');
    console.log('   Pattern:', pattern);
    console.log('   Starts with pattern:', startsWithPattern);
    console.log('   Contains pattern:', containsPattern);
    console.log('   Part count:', parts.length, '(requires >= 3)');
    console.log('');
    matched = true;
  }
});

if (!matched) {
  console.log('❌ NO MATCH FOUND');
}

console.log('='.repeat(70));
console.log('Additional test cases:');
console.log('='.repeat(70));

const testCases = [
  'click.company.com',
  'click.e.company.com',
  'email.shopify.com',
  'track.newsletter.com',
  'go.marketing.io',
  'sendgrid.net',
  'evil.com'
];

testCases.forEach(testHost => {
  let matchFound = false;

  for (const pattern of patterns) {
    const startsWithPattern = testHost.startsWith(pattern);
    const containsPattern = testHost.indexOf('.' + pattern) !== -1;
    const parts = testHost.split('.');
    const hasEnoughParts = parts.length >= 3;

    if ((startsWithPattern || containsPattern) && hasEnoughParts) {
      console.log('✅', testHost.padEnd(30), '→ matches pattern:', pattern);
      matchFound = true;
      break;
    }
  }

  if (!matchFound) {
    console.log('❌', testHost.padEnd(30), '→ no pattern match');
  }
});
