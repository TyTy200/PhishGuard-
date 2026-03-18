
const SERVER_URL = "http://localhost:5000";
let isEnabled = true;
let scanHistory = [];


chrome.runtime.onInstalled.addListener(() => {
    console.log('PhishGuard extension installed');
    chrome.storage.local.set({ enabled: true, blockedCount: 0, scannedCount: 0 });
});


async function checkServerStatus() {
    try {
        const response = await fetch(`${SERVER_URL}/api/extension/status`);
        const data = await response.json();
        console.log('✅ PhishGuard connected:', data);
        return true;
    } catch (error) {
        console.log('❌ Cannot connect to PhishGuard server');
        return false;
    }
}


async function scanURL(url, useRealAPI = false) {
    if (!isEnabled) return null;
    
    try {
        console.log(`🔍 Scanning URL: ${url}`);
        
        const response = await fetch(`${SERVER_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                url: url,
                force_real_api: useRealAPI,
                source: 'extension'
            })
        });
        
        const result = await response.json();
        
  
        scanHistory.push({
            url: url,
            result: result,
            timestamp: new Date().toISOString()
        });
        
  
        chrome.storage.local.get(['scannedCount'], (data) => {
            const newCount = (data.scannedCount || 0) + 1;
            chrome.storage.local.set({ scannedCount: newCount });
        });
        
        console.log('Scan result:', result);
        return result;
        
    } catch (error) {
        console.log('Error scanning URL:', error);
        return null;
    }
}


async function quickCheckURL(url) {
    try {
        const response = await fetch(`${SERVER_URL}/api/extension/check`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        return await response.json();
    } catch (error) {
        console.log('Quick check error:', error);
        return null;
    }
}


chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (!isEnabled) return;
    
  
    if (details.url.startsWith('chrome://') || 
        details.url.startsWith('about:') ||
        details.url.includes('localhost:5000') ||
        details.url.startsWith('moz-extension://') ||
        details.url.startsWith('chrome-extension://')) {
        return;
    }
    
    console.log(`🌐 User visited: ${details.url}`);
    
  
    const quickResult = await quickCheckURL(details.url);
    
    if (quickResult && quickResult.is_phishing === true) {
        console.log(`⚠️ Blocking phishing site: ${details.url}`);
        
     
        chrome.tabs.update(details.tabId, {
            url: `${SERVER_URL}/api/extension/blocked?url=${encodeURIComponent(details.url)}&risk=${quickResult.risk || 'HIGH'}&confidence=${quickResult.confidence || 95}`
        });
        
      
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: '⚠️ Phishing Site Blocked',
            message: `PhishGuard blocked ${new URL(details.url).hostname}`,
            priority: 2
        });
        
      
        chrome.storage.local.get(['blockedCount'], (data) => {
            const newCount = (data.blockedCount || 0) + 1;
            chrome.storage.local.set({ blockedCount: newCount });
        });
        
       
        setTimeout(() => {
            scanURL(details.url);
        }, 1000);
    } else {
       
        if (quickResult && !quickResult.cached) {
            setTimeout(() => {
                scanURL(details.url);
            }, 2000);
        }
    }
}, { url: [{ schemes: ['http', 'https'] }] });


chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "scan-link",
        title: "Scan Link with PhishGuard",
        contexts: ["link"]
    });
    
    chrome.contextMenus.create({
        id: "scan-page",
        title: "Scan Current Page",
        contexts: ["page"]
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "scan-link" && info.linkUrl) {
        chrome.tabs.create({ 
            url: `${SERVER_URL}/results?url=${encodeURIComponent(info.linkUrl)}` 
        });
    } else if (info.menuItemId === "scan-page" && tab.url) {
        chrome.tabs.create({ 
            url: `${SERVER_URL}/results?url=${encodeURIComponent(tab.url)}` 
        });
    }
});


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'toggle') {
        isEnabled = message.enabled;
        chrome.storage.local.set({ enabled: isEnabled });
        updateIcon();
        sendResponse({ success: true, enabled: isEnabled });
    }
    else if (message.action === 'getStatus') {
        sendResponse({ enabled: isEnabled });
    }
    else if (message.action === 'scanCurrentPage') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                scanURL(tabs[0].url).then(result => {
                    sendResponse({ success: true, result: result });
                });
            }
        });
        return true; 
    }
    else if (message.action === 'scanURL') {
        scanURL(message.url, message.useRealAPI).then(result => {
            sendResponse({ success: true, result: result });
        });
        return true; 
    }
});


chrome.storage.local.get(['enabled'], (result) => {
    isEnabled = result.enabled !== false;
    updateIcon();
});


checkServerStatus();