/* PhishWatch Content Script Additions for Test Helper Support
   
   Add this code to the END of your content.js file (inside the IIFE).
   This listens for test helper requests from the web page and forwards
   them to the background script.
*/

  // =========================
  // Test Helper Support
  // =========================
  window.addEventListener('phishwatch_test_request', function(evt) {
    try {
      var detail = evt.detail || {};
      var requestId = detail.requestId;
      var action = detail.action;
      var payload = detail.payload || {};
      
      pwLog('test helper request', { action: action, requestId: requestId });
      
      // Forward to background script
      chrome.runtime.sendMessage({
        type: 'PHISHWATCH_TEST_HELPER',
        action: action,
        payload: payload
      }, function(response) {
        // Send response back to web page
        window.dispatchEvent(new CustomEvent('phishwatch_test_response', {
          detail: {
            requestId: requestId,
            response: response || { ok: false, error: 'No response from background' }
          }
        }));
      });
    } catch (e) {
      pwLog('test helper error', { error: String(e) });
    }
  });
  
  pwLog('test helper listener registered');
