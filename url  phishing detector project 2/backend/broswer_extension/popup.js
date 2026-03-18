
const SERVER_URL = "http://localhost:5000";
let isEnabled = true;
let currentTabUrl = '';


const toggleSwitch = document.getElementById('protection-toggle');
const statusIndicator = document.getElementById('status-indicator');
const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const currentPageBtn = document.getElementById('current-page-btn');
const loading = document.getElementById('loading');
const result = document.getElementById('result');
const blockedCount = document.getElementById('blocked-count');
const scannedCount = document.getElementById('scanned-count');


document.addEventListener('DOMContentLoaded', async () => {
    console.log('PhishGuard popup loaded');
    

    chrome.storage.local.get(['enabled', 'blockedCount', 'scannedCount'], (data) => {
        isEnabled = data.enabled !== false;
        if (toggleSwitch) {
            toggleSwitch.checked = isEnabled;
        }
        updateStatus();
        
        blockedCount.textContent = data.blockedCount || 0;
        scannedCount.textContent = data.scannedCount || 0;
    });
    
    
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].url) {
            currentTabUrl = tabs[0].url;
            urlInput.value = currentTabUrl;
        }
    });
    
    
    await checkServerStatus();
});


if (toggleSwitch) {
    toggleSwitch.addEventListener('change', () => {
        isEnabled = toggleSwitch.checked;
        
        chrome.storage.local.set({ enabled: isEnabled });
        
     
        chrome.runtime.sendMessage({
            action: 'toggle',
            enabled: isEnabled
        }, (response) => {
            if (response && response.success) {
                updateStatus();
            }
        });
    });
}

function updateStatus() {
    if (!statusIndicator) return;
    
    if (isEnabled) {
        statusIndicator.className = 'status-indicator status-active';
        statusIndicator.innerHTML = '<div style="width: 8px; height: 8px; background: #06d6a0; border-radius: 50%; margin-right: 5px;"></div><span>ACTIVE</span>';
    } else {
        statusIndicator.className = 'status-indicator status-inactive';
        statusIndicator.innerHTML = '<div style="width: 8px; height: 8px; background: #ef476f; border-radius: 50%; margin-right: 5px;"></div><span>INACTIVE</span>';
    }
}


if (scanBtn) {
    scanBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        if (!url) {
            showError('Please enter a URL to scan');
            return;
        }
        
        await scanURL(url);
    });
}


if (currentPageBtn) {
    currentPageBtn.addEventListener('click', async () => {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            if (tabs[0]) {
                urlInput.value = tabs[0].url;
                await scanURL(tabs[0].url);
            }
        });
    });
}


async function scanURL(url) {
    showLoading();
    
    try {
        console.log(`Popup scanning URL: ${url}`);
        
        const response = await fetch(`${SERVER_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                url: url,
                source: 'extension',
                use_cache: true
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server error ${response.status}: ${errorText}`);
        }
        
        const data = await response.json();
        
        if (data.error) {
            showError(`Scan error: ${data.error}`);
            return;
        }
        
      
        chrome.storage.local.get(['scannedCount'], (result) => {
            const newCount = (result.scannedCount || 0) + 1;
            chrome.storage.local.set({ scannedCount: newCount });
            scannedCount.textContent = newCount;
        });
        
        showResult(data, url);
        
    } catch (error) {
        console.error('Popup scan error:', error);
        showError(`Failed to scan: ${error.message}`);
    }
}

function showLoading() {
    if (loading) loading.style.display = 'block';
    if (result) result.style.display = 'none';
}

function showError(message) {
    if (loading) loading.style.display = 'none';
    if (result) {
        result.style.display = 'block';
        result.className = 'result result-danger';
        result.innerHTML = `
            <div style="font-size: 20px; margin-bottom: 5px;">❌</div>
            <div>${message}</div>
        `;
    }
}


function showResult(data, originalUrl) {
    if (loading) loading.style.display = 'none';
    if (!result) return;
    
    result.style.display = 'block';
    
    if (data.is_phishing) {
        result.className = 'result result-danger';
        result.innerHTML = `
            <div style="font-size: 24px; margin-bottom: 10px;">⚠️</div>
            <div style="font-weight: bold; margin-bottom: 5px; font-size: 14px;">PHISHING DETECTED</div>
            <div style="font-size: 11px; margin-bottom: 10px; color: #666;">
                Confidence: ${data.confidence || 0}% | Risk: ${data.risk_level || 'HIGH'}
            </div>
            <button id="view-details" class="view-details-btn">View Full Report</button>
        `;
        
        
        if (data.action_taken === 'blocked') {
            chrome.storage.local.get(['blockedCount'], (result) => {
                const newCount = (result.blockedCount || 0) + 1;
                chrome.storage.local.set({ blockedCount: newCount });
                blockedCount.textContent = newCount;
            });
        }
    } else {
        result.className = 'result result-safe';
        result.innerHTML = `
            <div style="font-size: 24px; margin-bottom: 10px;">✅</div>
            <div style="font-weight: bold; margin-bottom: 5px; font-size: 14px;">SAFE URL</div>
            <div style="font-size: 11px; margin-bottom: 10px; color: #666;">
                Confidence: ${data.confidence || 0}% | Risk: ${data.risk_level || 'LOW'}
            </div>
            <button id="view-details" class="view-details-btn">View Full Report</button>
        `;
    }
    
 
    setTimeout(() => {
        const detailsBtn = document.getElementById('view-details');
        if (detailsBtn) {
            detailsBtn.addEventListener('click', () => {
             
                chrome.windows.create({
                    url: chrome.runtime.getURL(`results.html?url=${encodeURIComponent(originalUrl)}&scan_id=${data.scan_id || ''}`),
                    type: 'popup',
                    width: 850,
                    height: 700
                });
            });
        }
    }, 100);
}

async function checkServerStatus() {
    try {
        const response = await fetch(`${SERVER_URL}/api/extension/status`);
        const data = await response.json();
        console.log('Server status:', data);
        return true;
    } catch (error) {
        showError('Cannot connect to PhishGuard server. Make sure the Flask app is running on http://localhost:5000');
        return false;
    }
}


function addToggleSwitch() {
    const toggleContainer = document.querySelector('.toggle-container');
    if (toggleContainer && !document.getElementById('protection-toggle')) {
        toggleContainer.innerHTML = `
            <div class="toggle-label">
                <span>Real-time Protection</span>
                <label class="switch">
                    <input type="checkbox" id="protection-toggle" checked>
                    <span class="slider"></span>
                </label>
            </div>
            <p style="color: #6c757d; font-size: 12px; margin-top: 10px;">
                Blocks phishing sites automatically
            </p>
        `;
    }
}


function addViewDetailsCSS() {
    if (!document.querySelector('.view-details-btn')) {
        const style = document.createElement('style');
        style.textContent = `
            .view-details-btn {
                background: #4361ee;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 12px;
                cursor: pointer;
                margin-top: 10px;
                width: 100%;
                font-weight: 600;
            }
            .view-details-btn:hover {
                background: #3a56d4;
                transform: translateY(-1px);
            }
        `;
        document.head.appendChild(style);
    }
}


addToggleSwitch();
addViewDetailsCSS();