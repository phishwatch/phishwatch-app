/* PhishWatch Background Script Additions for Test Helper Support
   
   Add this message handler to your existing background.js to support
   the test helper storage operations.
   
   Simply add this code block to your existing message listener.
*/

// Add this to your existing chrome.runtime.onMessage.addListener callback:

// Test Helper Support (for SSO-safe gate testing)
if (msg.type === 'PHISHWATCH_TEST_HELPER') {
  const action = msg.action;
  const payload = msg.payload || {};
  
  if (action === 'storage.getAll') {
    chrome.storage.local.get(null, (data) => {
      sendResponse({
        ok: true,
        data: {
          baseline: data.pw_sequence_baseline || {},
          expectedOrigins: data.pw_expected_origins_by_page_origin || {},
          novelSequences: data.pw_novel_sequences || [],
          lastUpdated: data.pw_baseline_last_updated
        }
      });
    });
    return true; // Keep channel open for async response
  }
  
  if (action === 'storage.clear') {
    chrome.storage.local.remove([
      'pw_sequence_baseline',
      'pw_expected_origins_by_page_origin', 
      'pw_novel_sequences',
      'pw_baseline_last_updated'
    ], () => {
      sendResponse({ ok: true, message: 'Storage cleared' });
    });
    return true;
  }
  
  if (action === 'storage.seedOrigins') {
    const pageOrigin = payload.pageOrigin;
    const origins = payload.origins || [];
    
    chrome.storage.local.get(['pw_expected_origins_by_page_origin'], (data) => {
      const cache = data.pw_expected_origins_by_page_origin || {};
      cache[pageOrigin] = {
        origins: origins,
        last_seen: Date.now()
      };
      chrome.storage.local.set({ pw_expected_origins_by_page_origin: cache }, () => {
        sendResponse({ ok: true, message: 'Origins seeded', origins: origins });
      });
    });
    return true;
  }
  
  if (action === 'storage.getOrigins') {
    const pageOrigin = payload.pageOrigin;
    
    chrome.storage.local.get(['pw_expected_origins_by_page_origin'], (data) => {
      const cache = data.pw_expected_origins_by_page_origin || {};
      const entry = cache[pageOrigin];
      sendResponse({
        ok: true,
        data: entry ? entry.origins : [],
        entry: entry
      });
    });
    return true;
  }
  
  if (action === 'storage.getBaseline') {
    chrome.storage.local.get(['pw_sequence_baseline', 'pw_novel_sequences'], (data) => {
      sendResponse({
        ok: true,
        data: {
          baseline: data.pw_sequence_baseline || {},
          novelSequences: data.pw_novel_sequences || []
        }
      });
    });
    return true;
  }
  
  if (action === 'storage.clearBaseline') {
    chrome.storage.local.remove(['pw_sequence_baseline', 'pw_novel_sequences'], () => {
      sendResponse({ ok: true, message: 'Baseline cleared' });
    });
    return true;
  }
  
  // Unknown action
  sendResponse({ ok: false, error: 'Unknown test helper action: ' + action });
  return true;
}
