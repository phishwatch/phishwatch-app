const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
const fs = require('fs');
const path = require('path');

puppeteer.use(StealthPlugin());

// ANSI color codes for console output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

// Test configuration
const EXTENSION_PATH = path.resolve(__dirname, 'extension');
const SCREENSHOT_DIR = path.resolve(__dirname, 'test-screenshots');
const REPORT_FILE = path.resolve(__dirname, 'real-world-test-report.md');
const PAGE_LOAD_TIMEOUT = 5000; // 5 seconds

// List of websites to test
const TEST_SITES = [
  'https://google.com',
  'https://github.com',
  'https://gitlab.com',
  'https://login.microsoftonline.com',
  'https://aws.amazon.com',
  'https://stripe.com',
  'https://paypal.com',
  'https://notion.so',
  'https://figma.com',
  'https://slack.com',
  'https://discord.com',
  'https://reddit.com',
  'https://twitter.com',
  'https://linkedin.com',
  'https://facebook.com',
  'https://amazon.com',
  'https://ebay.com',
  'https://shopify.com',
  'https://zoom.us',
  'https://salesforce.com'
];

// Create screenshot directory if it doesn't exist
function ensureDirectoryExists(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`${colors.blue}📁 Created directory: ${dir}${colors.reset}`);
  }
}

// Format site name for file naming
function formatSiteName(url) {
  return url.replace(/https?:\/\//, '').replace(/\//g, '_').replace(/\./g, '-');
}

// Test a single website
async function testWebsite(browser, url, index) {
  const siteName = formatSiteName(url);
  const result = {
    url,
    siteName,
    status: 'pending',
    errors: [],
    warnings: [],
    phishwatchMessages: [],
    screenshot: '',
    loadTime: 0,
    memoryUsage: 0,
    inputFieldFound: false,
    contentScriptActive: false
  };

  console.log(`\n${colors.cyan}${colors.bold}[${index + 1}/${TEST_SITES.length}] Testing: ${url}${colors.reset}`);

  const page = await browser.newPage();

  try {
    // Collect console messages
    page.on('console', msg => {
      const text = msg.text();
      if (text.includes('[PhishWatch]')) {
        result.phishwatchMessages.push(text);
        console.log(`${colors.blue}  📝 ${text}${colors.reset}`);

        if (text.includes('content.js loaded')) {
          result.contentScriptActive = true;
        }
      }
    });

    // Collect page errors
    page.on('pageerror', error => {
      result.errors.push(error.message);
      console.log(`${colors.red}  ❌ Page Error: ${error.message}${colors.reset}`);
    });

    // Collect console errors
    page.on('console', msg => {
      if (msg.type() === 'error') {
        const text = msg.text();
        result.errors.push(text);
        console.log(`${colors.red}  ❌ Console Error: ${text}${colors.reset}`);
      } else if (msg.type() === 'warning') {
        result.warnings.push(msg.text());
      }
    });

    // Start timing
    const startTime = Date.now();

    // Navigate to the website
    await page.goto(url, {
      waitUntil: 'networkidle2',
      timeout: 30000
    });

    // Wait for page to fully load
    await new Promise(resolve => setTimeout(resolve, PAGE_LOAD_TIMEOUT));

    // Calculate load time
    result.loadTime = Date.now() - startTime;

    // Get memory usage
    const metrics = await page.metrics();
    result.memoryUsage = Math.round(metrics.JSHeapUsedSize / 1024 / 1024); // Convert to MB

    // Check for PhishWatch content script injection
    const hasPhishWatch = await page.evaluate(() => {
      return window.hasOwnProperty('__phishwatch_injected__') ||
             document.querySelector('[data-phishwatch]') !== null;
    });

    if (hasPhishWatch) {
      result.contentScriptActive = true;
    }

    // Try to find and interact with first input field
    try {
      const inputField = await page.$('input[type="text"], input[type="email"], input[type="password"], input:not([type])');
      if (inputField) {
        result.inputFieldFound = true;
        console.log(`${colors.green}  ✓ Input field found${colors.reset}`);

        // Try to focus on it
        await inputField.click();
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    } catch (err) {
      console.log(`${colors.yellow}  ⚠ No input field found or unable to interact${colors.reset}`);
    }

    // Take screenshot
    const screenshotPath = path.join(SCREENSHOT_DIR, `${siteName}.png`);
    await page.screenshot({
      path: screenshotPath,
      fullPage: false // Only capture viewport
    });
    result.screenshot = screenshotPath;

    // Determine status
    if (result.errors.length === 0) {
      result.status = 'pass';
      console.log(`${colors.green}${colors.bold}  ✓ PASS${colors.reset}`);
    } else if (result.errors.some(e => e.includes('PhishWatch') || e.includes('phishwatch'))) {
      result.status = 'fail';
      console.log(`${colors.red}${colors.bold}  ✗ FAIL (PhishWatch errors detected)${colors.reset}`);
    } else {
      result.status = 'pass-with-warnings';
      console.log(`${colors.yellow}${colors.bold}  ⚠ PASS WITH WARNINGS${colors.reset}`);
    }

    // Log metrics
    console.log(`${colors.cyan}  📊 Load time: ${result.loadTime}ms | Memory: ${result.memoryUsage}MB${colors.reset}`);
    console.log(`${colors.cyan}  🔌 Content script active: ${result.contentScriptActive ? 'Yes' : 'No'}${colors.reset}`);

  } catch (error) {
    result.status = 'fail';
    result.errors.push(error.message);
    console.log(`${colors.red}${colors.bold}  ✗ FAIL: ${error.message}${colors.reset}`);
  } finally {
    await page.close();
  }

  return result;
}

// Generate markdown report
function generateReport(results, startTime, endTime) {
  const duration = Math.round((endTime - startTime) / 1000);
  const passed = results.filter(r => r.status === 'pass').length;
  const passedWithWarnings = results.filter(r => r.status === 'pass-with-warnings').length;
  const failed = results.filter(r => r.status === 'fail').length;

  let report = `# PhishWatch Real-World Testing Report\n\n`;
  report += `**Test Date:** ${new Date().toISOString()}\n`;
  report += `**Duration:** ${duration} seconds\n`;
  report += `**Total Sites Tested:** ${results.length}\n\n`;

  // Summary
  report += `## Summary\n\n`;
  report += `- ✅ **Passed:** ${passed}\n`;
  report += `- ⚠️ **Passed with Warnings:** ${passedWithWarnings}\n`;
  report += `- ❌ **Failed:** ${failed}\n`;
  report += `- **Success Rate:** ${Math.round(((passed + passedWithWarnings) / results.length) * 100)}%\n\n`;

  // Results table
  report += `## Test Results\n\n`;
  report += `| # | Website | Status | Errors | Warnings | Content Script | Input Field | Load Time | Memory |\n`;
  report += `|---|---------|--------|--------|----------|----------------|-------------|-----------|--------|\n`;

  results.forEach((result, index) => {
    const statusEmoji = result.status === 'pass' ? '✅' :
                       result.status === 'pass-with-warnings' ? '⚠️' : '❌';
    const contentScriptStatus = result.contentScriptActive ? '✓' : '✗';
    const inputFieldStatus = result.inputFieldFound ? '✓' : '✗';

    report += `| ${index + 1} | [${result.url}](${result.url}) | ${statusEmoji} ${result.status} | ${result.errors.length} | ${result.warnings.length} | ${contentScriptStatus} | ${inputFieldStatus} | ${result.loadTime}ms | ${result.memoryUsage}MB |\n`;
  });

  // PhishWatch errors section
  const phishwatchErrors = results.filter(r =>
    r.errors.some(e => e.toLowerCase().includes('phishwatch'))
  );

  if (phishwatchErrors.length > 0) {
    report += `\n## PhishWatch Errors Found\n\n`;
    phishwatchErrors.forEach(result => {
      report += `### ${result.url}\n\n`;
      result.errors.forEach(error => {
        if (error.toLowerCase().includes('phishwatch')) {
          report += `- \`${error}\`\n`;
        }
      });
      report += `\n`;
    });
  }

  // Sites with no content script injection
  const noContentScript = results.filter(r => !r.contentScriptActive);
  if (noContentScript.length > 0) {
    report += `\n## Sites Without Content Script\n\n`;
    report += `These sites did not show evidence of PhishWatch content script injection:\n\n`;
    noContentScript.forEach(result => {
      report += `- ${result.url}\n`;
    });
    report += `\n`;
  }

  // Performance summary
  report += `\n## Performance Summary\n\n`;
  const avgLoadTime = Math.round(results.reduce((sum, r) => sum + r.loadTime, 0) / results.length);
  const avgMemory = Math.round(results.reduce((sum, r) => sum + r.memoryUsage, 0) / results.length);
  const maxLoadTime = Math.max(...results.map(r => r.loadTime));
  const maxMemory = Math.max(...results.map(r => r.memoryUsage));

  report += `- **Average Load Time:** ${avgLoadTime}ms\n`;
  report += `- **Maximum Load Time:** ${maxLoadTime}ms\n`;
  report += `- **Average Memory Usage:** ${avgMemory}MB\n`;
  report += `- **Maximum Memory Usage:** ${maxMemory}MB\n\n`;

  // PhishWatch messages
  report += `\n## PhishWatch Console Messages\n\n`;
  results.forEach(result => {
    if (result.phishwatchMessages.length > 0) {
      report += `### ${result.url}\n\n`;
      result.phishwatchMessages.forEach(msg => {
        report += `- \`${msg}\`\n`;
      });
      report += `\n`;
    }
  });

  // Screenshots
  report += `\n## Screenshots\n\n`;
  report += `Screenshots are saved in the \`test-screenshots/\` directory:\n\n`;
  results.forEach((result, index) => {
    if (result.screenshot) {
      report += `${index + 1}. **${result.url}**: \`${path.basename(result.screenshot)}\`\n`;
    }
  });

  report += `\n---\n`;
  report += `*Generated by PhishWatch Automated Testing System*\n`;

  return report;
}

// Main test runner
async function runTests() {
  console.log(`${colors.bold}${colors.cyan}`);
  console.log('╔═══════════════════════════════════════════════════╗');
  console.log('║   PhishWatch Real-World Testing System           ║');
  console.log('╚═══════════════════════════════════════════════════╝');
  console.log(colors.reset);

  // Ensure directories exist
  ensureDirectoryExists(SCREENSHOT_DIR);

  // Check extension exists
  if (!fs.existsSync(EXTENSION_PATH)) {
    console.log(`${colors.red}❌ Extension directory not found: ${EXTENSION_PATH}${colors.reset}`);
    process.exit(1);
  }

  console.log(`${colors.green}✓ Extension found: ${EXTENSION_PATH}${colors.reset}`);
  console.log(`${colors.green}✓ Testing ${TEST_SITES.length} websites${colors.reset}`);

  const startTime = Date.now();

  // Launch browser with extension
  console.log(`\n${colors.blue}🚀 Launching browser with PhishWatch extension...${colors.reset}`);

  const browser = await puppeteer.launch({
    headless: false, // Set to false so you can watch
    args: [
      `--disable-extensions-except=${EXTENSION_PATH}`,
      `--load-extension=${EXTENSION_PATH}`,
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-blink-features=AutomationControlled'
    ],
    defaultViewport: {
      width: 1920,
      height: 1080
    }
  });

  const results = [];

  // Test each website
  for (let i = 0; i < TEST_SITES.length; i++) {
    const result = await testWebsite(browser, TEST_SITES[i], i);
    results.push(result);

    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  const endTime = Date.now();

  // Close browser
  await browser.close();

  // Generate report
  console.log(`\n${colors.cyan}📝 Generating report...${colors.reset}`);
  const report = generateReport(results, startTime, endTime);
  fs.writeFileSync(REPORT_FILE, report);
  console.log(`${colors.green}✓ Report saved to: ${REPORT_FILE}${colors.reset}`);

  // Print summary
  const passed = results.filter(r => r.status === 'pass').length;
  const passedWithWarnings = results.filter(r => r.status === 'pass-with-warnings').length;
  const failed = results.filter(r => r.status === 'fail').length;

  console.log(`\n${colors.bold}${colors.cyan}═══════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.bold}Test Summary:${colors.reset}`);
  console.log(`${colors.green}  ✅ Passed: ${passed}${colors.reset}`);
  console.log(`${colors.yellow}  ⚠️  Passed with Warnings: ${passedWithWarnings}${colors.reset}`);
  console.log(`${colors.red}  ❌ Failed: ${failed}${colors.reset}`);
  console.log(`${colors.bold}  Success Rate: ${Math.round(((passed + passedWithWarnings) / results.length) * 100)}%${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════${colors.reset}\n`);

  process.exit(failed > 0 ? 1 : 0);
}

// Run the tests
runTests().catch(error => {
  console.error(`${colors.red}${colors.bold}Fatal Error:${colors.reset}`, error);
  process.exit(1);
});
