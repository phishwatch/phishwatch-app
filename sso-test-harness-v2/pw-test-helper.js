/* PhishWatch Test Helper v2 - Uses window messaging to content script
   
   Web pages cannot directly message extensions. This helper posts messages
   to the window, which the content script listens for and forwards to background.
*/

(function() {
  'use strict';
  
  var requestId = 0;
  var pendingRequests = {};
  
  // Listen for responses from content script
  window.addEventListener('phishwatch_test_response', function(evt) {
    var detail = evt.detail || {};
    var id = detail.requestId;
    var callback = pendingRequests[id];
    if (callback) {
      delete pendingRequests[id];
      callback(detail.response);
    }
  });
  
  function sendRequest(action, payload) {
    return new Promise(function(resolve, reject) {
      var id = ++requestId;
      var timeoutId;
      
      pendingRequests[id] = function(response) {
        clearTimeout(timeoutId);
        if (response && response.ok) {
          resolve(response);
        } else {
          reject(new Error(response ? response.error : 'No response'));
        }
      };
      
      // Timeout after 5 seconds
      timeoutId = setTimeout(function() {
        delete pendingRequests[id];
        reject(new Error('Request timeout - make sure content script has test helper support'));
      }, 5000);
      
      // Dispatch request to content script
      window.dispatchEvent(new CustomEvent('phishwatch_test_request', {
        detail: {
          requestId: id,
          action: action,
          payload: payload || {}
        }
      }));
    });
  }
  
  // Expose helper functions globally
  window.PhishWatchTestHelper = {
    
    isAvailable: function() {
      return true; // We'll know when the request times out
    },
    
    getStorage: function() {
      return sendRequest('storage.getAll');
    },
    
    clearStorage: function() {
      return sendRequest('storage.clear');
    },
    
    seedExpectedOrigins: function(origins) {
      return sendRequest('storage.seedOrigins', {
        pageOrigin: window.location.origin,
        origins: origins
      });
    },
    
    getExpectedOrigins: function() {
      return sendRequest('storage.getOrigins', {
        pageOrigin: window.location.origin
      });
    },
    
    getBaseline: function() {
      return sendRequest('storage.getBaseline');
    },
    
    clearBaseline: function() {
      return sendRequest('storage.clearBaseline');
    }
  };
  
  console.log('[PhishWatch Test Helper] v2 Loaded (window messaging mode)');
})();
