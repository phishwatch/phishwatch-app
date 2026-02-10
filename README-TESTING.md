# PhishWatch Real-World Testing Guide

This automated testing system validates the PhishWatch browser extension against 20 real-world websites to ensure it works correctly in production environments.

## Overview

The testing system uses Puppeteer to:
- Load the PhishWatch extension in a real Chrome browser
- Navigate to 20 popular websites
- Monitor console messages and errors
- Verify content script injection
- Test interaction with input fields
- Capture performance metrics
- Generate detailed reports with screenshots

## Prerequisites

- Node.js 16.x or higher
- npm or yarn
- Chrome/Chromium browser (automatically managed by Puppeteer)

## Installation

1. Install dependencies:
```bash
npm install
```

This will install:
- `puppeteer` - Browser automation library
- `puppeteer-extra` - Plugin support for Puppeteer
- `puppeteer-extra-plugin-stealth` - Makes automation less detectable

## Running Tests

### Run All Tests

```bash
npm test
```

or

```bash
npm run test:sites
```

or directly:

```bash
node test-real-world-sites.js
```

### What Happens During Tests

1. **Browser Launch**: A visible Chrome browser window opens with PhishWatch installed
2. **Sequential Testing**: Each of the 20 websites is tested one by one
3. **Per-Site Testing**:
   - Navigate to the URL
   - Wait 5 seconds for full page load
   - Monitor console for PhishWatch messages
   - Detect any JavaScript errors
   - Check if content script is active
   - Find and interact with input fields
   - Capture a screenshot
   - Record performance metrics
4. **Report Generation**: Creates a detailed markdown report
5. **Browser Closes**: Automatically closes when done

### Test Duration

- Expected runtime: 3-5 minutes for all 20 sites
- Each site takes ~10-15 seconds (5s load + interaction + screenshot)

## Understanding Results

### Console Output

The test runner provides colored console output:

- 🟢 **Green** = Pass
- 🟡 **Yellow** = Warning (non-critical issues)
- 🔴 **Red** = Fail (critical errors)
- 🔵 **Blue** = Information

Example output:
```
[1/20] Testing: https://google.com
  📝 [PhishWatch] content.js loaded
  ✓ Input field found
  ✓ PASS
  📊 Load time: 2341ms | Memory: 45MB
  🔌 Content script active: Yes
```

### Report File

After tests complete, check `real-world-test-report.md` for:

1. **Summary Table**: Overview of all sites with pass/fail status
2. **Error Details**: Specific errors encountered on each site
3. **Performance Metrics**: Load times and memory usage
4. **PhishWatch Messages**: All console logs from the extension
5. **Screenshot References**: Links to captured screenshots

### Screenshots

Screenshots are saved in `test-screenshots/` directory with filenames like:
- `google-com.png`
- `github-com.png`
- `login-microsoftonline-com.png`

### Success Criteria

A site **passes** if:
- No PhishWatch-specific errors occur
- Page loads without crashing
- No critical JavaScript errors

A site **passes with warnings** if:
- Some non-critical errors occur (e.g., CORS, network issues)
- PhishWatch is functioning but site has unrelated issues

A site **fails** if:
- PhishWatch throws errors
- Content script fails to inject
- Critical JavaScript errors occur

## Interpreting Common Issues

### Content Script Not Active

If "Content script active: No" appears:
- Check `manifest.json` content script permissions
- Verify the site URL matches manifest patterns
- Some sites may block extension scripts

### Input Field Not Found

If "No input field found" appears:
- The page doesn't have standard input fields
- This is informational, not a failure

### Page Load Timeouts

If tests timeout:
- Increase timeout in `test-real-world-sites.js` (line 20)
- Check internet connection
- Some sites may be slow or blocking automated access

### CORS Errors in Console

CORS errors are common and typically not PhishWatch issues:
- These are expected on many sites
- Only PhishWatch-specific errors matter

## Cleaning Up

Remove test artifacts:

```bash
npm run clean
```

This deletes:
- All screenshots in `test-screenshots/`
- The markdown report

## Troubleshooting

### Issue: "Extension directory not found"

**Solution**: Ensure you're running tests from the project root and `./extension` directory exists.

### Issue: Browser doesn't open

**Solution**:
- Check if Chrome/Chromium is installed
- Try running with `--no-sandbox` (already enabled)
- On Linux, may need additional dependencies

### Issue: Tests hang or freeze

**Solution**:
- Close the browser manually and restart tests
- Check for popup dialogs blocking automation
- Some sites have aggressive bot detection

### Issue: Many failures on first run

**Solution**:
- First run downloads Chromium (~150MB), may cause timeouts
- Re-run tests after Puppeteer setup completes
- Check internet connection stability

### Issue: Memory errors

**Solution**:
- Close other Chrome instances
- Increase Node.js memory: `node --max-old-space-size=4096 test-real-world-sites.js`

## Customization

### Adding More Sites

Edit `test-real-world-sites.js` line 14-35 and add URLs to the `TEST_SITES` array:

```javascript
const TEST_SITES = [
  'https://google.com',
  'https://your-site.com',  // Add here
  // ... more sites
];
```

### Changing Wait Time

Modify `PAGE_LOAD_TIMEOUT` at line 20:

```javascript
const PAGE_LOAD_TIMEOUT = 5000; // milliseconds
```

### Running in Headless Mode

In `test-real-world-sites.js` around line 290, change:

```javascript
headless: false,  // Change to true
```

Note: Headless mode may behave differently than visible mode.

### Adjusting Viewport Size

Modify viewport settings around line 298:

```javascript
defaultViewport: {
  width: 1920,  // Your width
  height: 1080  // Your height
}
```

## CI/CD Integration

To run in CI/CD pipelines:

1. Set headless mode to `true`
2. Add to your CI script:

```yaml
# GitHub Actions example
- name: Install dependencies
  run: npm install

- name: Run PhishWatch tests
  run: npm test

- name: Upload screenshots
  if: failure()
  uses: actions/upload-artifact@v3
  with:
    name: test-screenshots
    path: test-screenshots/
```

## Best Practices

1. **Run tests regularly** - Before each release
2. **Review reports carefully** - Don't just look at pass/fail counts
3. **Check screenshots** - Visual verification catches UI issues
4. **Monitor performance** - Watch for memory leaks or slow loads
5. **Update test sites** - Keep the list relevant to your users

## Support

If you encounter issues:

1. Check the console output for specific errors
2. Review the generated markdown report
3. Examine screenshots for visual clues
4. Check PhishWatch logs: `[PhishWatch]` prefix in console

## File Structure

```
phishwatch/
├── extension/              # PhishWatch extension files
├── test-screenshots/       # Generated screenshots (gitignored)
├── test-real-world-sites.js    # Main test script
├── real-world-test-report.md   # Generated report
├── package.json            # Dependencies
└── README-TESTING.md       # This file
```

## License

Same as PhishWatch project.
