
const SERVER_URL = "http://localhost:5000";


const loading = document.getElementById('loading');
const resultsContainer = document.getElementById('results-container');
const backBtn = document.getElementById('back-btn');
const rescanBtn = document.getElementById('rescan-btn');
const openWebsiteBtn = document.getElementById('open-website-btn');


function getQueryParam(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}


function getCurrentTime() {
    const now = new Date();
    return {
        iso: now.toISOString(),
        human: now.toLocaleString('en-GB', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }),
        date: now.toLocaleDateString('en-GB'),
        time: now.toLocaleTimeString('en-GB'),
        datetime: `${now.toLocaleDateString('en-GB')} ${now.toLocaleTimeString('en-GB')}`
    };
}


function formatTimestamp(timestamp) {
    if (!timestamp) {
     
        const now = new Date();
        return now.toLocaleString('en-GB', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }
    
    try {
        
        let date;
        if (typeof timestamp === 'string') {
          
            const cleanTimestamp = timestamp.replace('Z', '').split('+')[0];
            date = new Date(cleanTimestamp);
        } else {
            date = new Date(timestamp);
        }
        
        if (isNaN(date.getTime())) {
            
            return new Date().toLocaleString('en-GB', {
                day: '2-digit',
                month: 'short',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
        }
        
        return date.toLocaleString('en-GB', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    } catch (e) {
    
        const now = new Date();
        return now.toLocaleString('en-GB', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }
}

function updateRealTimeClock() {
    const updateTime = () => {
        const now = new Date();
        const timeString = now.toLocaleString('en-GB', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
        
       
        const currentTimeElement = document.getElementById('current-time');
        if (currentTimeElement) {
            currentTimeElement.textContent = timeString;
        }
    };
    

    updateTime();
    setInterval(updateTime, 1000);
}


function addTimeSection(data) {
    const currentTime = getCurrentTime();
    const scanTime = data.timestamp_human || formatTimestamp(data.timestamp) || currentTime.human;
    const scanDuration = data.scan_duration_seconds || 0;
    
  
    const timeSection = document.createElement('div');
    timeSection.className = 'time-section';
    timeSection.innerHTML = `
        <h3 style="color: #4361ee; margin-bottom: 15px;">
            ⏰ Scan Timing Information
        </h3>
        <div class="time-grid">
            <div class="time-item">
                <div class="time-value">${scanTime.split(',')[0]}</div>
                <div class="time-label">Scan Date</div>
            </div>
            <div class="time-item">
                <div class="time-value">${scanTime.split(',')[1]?.trim() || currentTime.time}</div>
                <div class="time-label">Scan Time</div>
            </div>
            <div class="time-item">
                <div class="time-value">${scanDuration > 0 ? scanDuration.toFixed(2) + 's' : '< 0.1s'}</div>
                <div class="time-label">Duration</div>
            </div>
        </div>
        <p style="color: #6c757d; font-size: 12px; margin-top: 15px; text-align: center;">
            Last updated: ${currentTime.datetime}
        </p>
    `;
    
   
    const scanSummary = document.querySelector('.scan-summary');
    if (scanSummary) {
        scanSummary.parentNode.insertBefore(timeSection, scanSummary.nextSibling);
    }
}



function formatDomainAge(age) {
    if (!age || age === 'Unknown') return 'Unknown';
    
    if (typeof age === 'number') {
        if (age < 30) return `${age} days (New)`;
        if (age < 365) return `${Math.floor(age / 30)} months`;
        return `${Math.floor(age / 365)} years`;
    }
    
    return age;
}


function getRiskBadgeClass(riskLevel) {
    const risk = (riskLevel || '').toUpperCase();
    
    switch(risk) {
        case 'CRITICAL':
        case 'HIGH':
            return 'badge-danger';
        case 'MEDIUM':
            return 'badge-warning';
        case 'LOW':
        case 'VERY LOW':
            return 'badge-success';
        default:
            return 'badge-info';
    }
}


function getVirusTotalLink(url) {
    try {
        const domain = new URL(url).hostname;
        return `https://www.virustotal.com/gui/domain/${domain}`;
    } catch (e) {
        return `https://www.virustotal.com/gui/home/search`;
    }
}


function parseSources(sources) {
    if (!sources || !Array.isArray(sources)) return [];
    
    const sourceItems = [];
    
    sources.forEach(source => {
        if (source.includes('ml:')) {
            sourceItems.push({
                type: 'ml',
                icon: '🤖',
                text: `ML Model: ${source.split(':')[1]}`,
                color: 'source-ml'
            });
        } else if (source.includes('virustotal') || source.includes('vt')) {
            sourceItems.push({
                type: 'vt',
                icon: '🛡️',
                text: 'VirusTotal Analysis',
                color: 'source-vt'
            });
        } else if (source.includes('local-blacklist')) {
            sourceItems.push({
                type: 'local',
                icon: '📋',
                text: 'Local Blacklist',
                color: 'source-local'
            });
        } else if (source.includes('local-whitelist')) {
            sourceItems.push({
                type: 'local',
                icon: '✅',
                text: 'Local Whitelist',
                color: 'source-local'
            });
        } else if (source.includes('heuristics')) {
            sourceItems.push({
                type: 'heuristics',
                icon: '🔍',
                text: 'Heuristic Analysis',
                color: 'source-heuristics'
            });
        }
    });
    
    return sourceItems;
}

async function loadResults() {
    const url = getQueryParam('url');
    const scanId = getQueryParam('scan_id');
    
    if (!url) {
        showError('No URL provided in query parameters');
        return;
    }
    
    console.log('Loading results for URL:', url, 'Scan ID:', scanId);
    
    showLoading();
    
    try {
      
        try {
            const statusResponse = await fetch(`${SERVER_URL}/api/extension/status`);
            if (!statusResponse.ok) {
                throw new Error(`Server status: ${statusResponse.status}`);
            }
            const statusData = await statusResponse.json();
            console.log('Server status:', statusData);
        } catch (error) {
            console.error('Server status check failed:', error);
           
        }
        
       
        let result;
        
        if (scanId) {
          
            result = await getScanFromHistory(scanId, url);
        }
        
       
        if (!result) {
            result = await scanURL(url);
        }
        
        if (result && result.error) {
            showError(`Scan error: ${result.error}`);
        } else if (result) {
            displayResults(result, url);
        } else {
            showError('No data received from server');
        }
        
    } catch (error) {
        console.error('Scan error:', error);
        showError(`Failed to scan URL: ${error.message || error}`);
    }
}

function displayResults(data, originalUrl) {
    console.log('Displaying results:', data);
    
    if (loading) loading.style.display = 'none';
    if (!resultsContainer) return;
    
    resultsContainer.style.display = 'block';
    
  
    const verdictText = document.getElementById('verdict-text');
    const verdictIcon = document.getElementById('verdict-icon');
    
    if (data.is_phishing) {
        if (verdictText) {
            verdictText.textContent = 'PHISHING DETECTED';
            verdictText.className = 'verdict-text verdict-danger';
        }
        if (verdictIcon) verdictIcon.textContent = '⚠️';
    } else {
        if (verdictText) {
            verdictText.textContent = 'SAFE URL';
            verdictText.className = 'verdict-text verdict-safe';
        }
        if (verdictIcon) verdictIcon.textContent = '✅';
    }
    
 
    const confidenceBadge = document.getElementById('confidence-badge');
    if (confidenceBadge) {
        confidenceBadge.textContent = `Confidence: ${data.confidence || 0}%`;
    }
    

    const scannedUrl = document.getElementById('scanned-url');
    if (scannedUrl) {
        scannedUrl.textContent = originalUrl || data.url || 'Unknown URL';
    }

    const domainValue = document.getElementById('domain-value');
    if (domainValue) {
        domainValue.textContent = data.domain || 'Unknown';
    }
    
    const domainAge = document.getElementById('domain-age');
    if (domainAge) {
        domainAge.textContent = formatDomainAge(data.domain_age);
    }
    
    const sslStatus = document.getElementById('ssl-status');
    if (sslStatus) {
        sslStatus.textContent = data.has_ssl ? 'Secure (HTTPS)' : 'Not Secure (HTTP)';
    }
    
  
    const scanId = document.getElementById('scan-id');
    if (scanId) {
        scanId.textContent = data.scan_id || 'N/A';
    }
    
    const analysisTime = document.getElementById('analysis-time');
    if (analysisTime) {
        analysisTime.textContent = data.timestamp_human || formatTimestamp(data.timestamp) || 'Just now';
    }
    
    const scanDuration = document.getElementById('scan-duration');
    if (scanDuration) {
        const duration = data.scan_duration_seconds || 0;
        scanDuration.textContent = duration > 0 ? `${duration.toFixed(2)}s` : '< 0.1s';
    }
    
    const riskLevelBadge = document.getElementById('risk-level-badge');
    if (riskLevelBadge) {
        const riskLevel = data.risk_level || 'UNKNOWN';
        riskLevelBadge.textContent = riskLevel;
        riskLevelBadge.className = `badge ${getRiskBadgeClass(riskLevel)}`;
    }
    
 
    updateVirusTotalInfo(data);
    
    updateDetectionSources(data);
    
    const currentTimeElement = document.getElementById('current-time');
    if (currentTimeElement) {
        const now = new Date();
        currentTimeElement.textContent = now.toLocaleString('en-GB', {
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }
    
    const footerTimestamp = document.getElementById('footer-timestamp');
    if (footerTimestamp) {
        footerTimestamp.textContent = `Last updated: ${new Date().toLocaleString()}`;
    }
    
    addTimeSection(data);
}

function updateVirusTotalInfo(data) {
    const vtSource = document.getElementById('vt-source');
    const vtLastCheck = document.getElementById('vt-last-check');
    const vtStatusBadge = document.getElementById('vt-status-badge');
    
    if (data.virustotal_result) {
        const vt = data.virustotal_result;
        
        if (vtSource) {
            let sourceText = vt.source ? vt.source.replace(/_/g, ' ') : 'Not available';
            if (vt.source === 'virustotal_mock' || vt.source === 'virustotal_mock_fallback') {
                sourceText = 'Mock Data';
            } else if (vt.source === 'virustotal_submitted') {
                sourceText = 'Submitted for Analysis';
            }
            vtSource.textContent = sourceText;
        }
        
        if (vtLastCheck) {
            vtLastCheck.textContent = vt.last_analysis_human || 'Never analyzed';
        }
        
        if (vtStatusBadge) {
            if (vt.api_key_valid === false) {
                vtStatusBadge.textContent = 'API Key Invalid';
                vtStatusBadge.className = 'badge badge-danger';
            } 
            else if (vt.source === 'virustotal_mock' || vt.source === 'virustotal_mock_fallback') {
                vtStatusBadge.textContent = 'Mock Data';
                vtStatusBadge.className = 'badge badge-warning';
            }
            else if (vt.source === 'virustotal_submitted') {
                vtStatusBadge.textContent = 'Submitted';
                vtStatusBadge.className = 'badge badge-info';
            }
            else if (vt.error && vt.source !== 'virustotal_auth_error') {
                vtStatusBadge.textContent = 'API Error';
                vtStatusBadge.className = 'badge badge-warning';
            }
            else {
                vtStatusBadge.textContent = 'Connected';
                vtStatusBadge.className = 'badge badge-success';
            }
        }
    } else {
        if (vtSource) vtSource.textContent = 'Not available';
        if (vtLastCheck) vtLastCheck.textContent = 'N/A';
        if (vtStatusBadge) {
            vtStatusBadge.textContent = 'Disabled';
            vtStatusBadge.className = 'badge badge-info';
        }
    }
}

function updateDetectionSources(data) {
    const sourcesGrid = document.getElementById('sources-grid');
    if (!sourcesGrid) return;
    
    sourcesGrid.innerHTML = '';
    
    const sources = parseSources(data.verdict_sources || []);
    
    if (sources.length === 0) {
        sourcesGrid.innerHTML = '<div style="color: #6c757d; text-align: center; grid-column: 1/-1;">No detection sources available</div>';
        return;
    }
    
    sources.forEach(source => {
        const sourceDiv = document.createElement('div');
        sourceDiv.className = 'source-item';
        sourceDiv.innerHTML = `
            <div class="source-icon ${source.color}">${source.icon}</div>
            <div class="source-text">${source.text}</div>
        `;
        sourcesGrid.appendChild(sourceDiv);
    });
}
async function getScanFromHistory(scanId, url) {
    try {
        console.log('Looking for scan in history:', scanId);

        const response = await fetch(`${SERVER_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                url: url,
                source: 'extension_results',
                use_cache: true
            })
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('Found scan result:', data);
            return data;
        }
    } catch (error) {
        console.error('Error getting scan from history:', error);
    }
    return null;
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('Results page loaded');
    
    updateRealTimeClock();
    
    loadResults();

    if (backBtn) {
        backBtn.addEventListener('click', function() {
            window.close();
        });
    }
    
    if (rescanBtn) {
        rescanBtn.addEventListener('click', function() {
            const url = getQueryParam('url');
            if (url) {
                loadResults();
            }
        });
    }
    
    if (openWebsiteBtn) {
        openWebsiteBtn.addEventListener('click', function() {
            const url = getQueryParam('url');
            if (url) {
                window.open(`http://localhost:5000?url=${encodeURIComponent(url)}`, '_blank');
            }
        });
    }
});
function showLoading() {
    if (loading) loading.style.display = 'flex';
    if (resultsContainer) resultsContainer.style.display = 'none';
}
function showError(message) {
    if (loading) loading.style.display = 'none';
    
    if (!resultsContainer) {
        alert(message);
        return;
    }
    
    resultsContainer.style.display = 'block';
    resultsContainer.innerHTML = `
        <div class="error-message" style="text-align: center; padding: 50px;">
            <div style="font-size: 48px; margin-bottom: 20px; color: #ef476f;">❌</div>
            <h3 style="color: #ef476f; margin-bottom: 10px;">Error Loading Results</h3>
            <p style="color: #6c757d; margin-bottom: 20px;">${message}</p>
            <button onclick="window.close()" style="background: #4361ee; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
                Close Window
            </button>
        </div>
    `;
}
