
console.log('PhishGuard content script loaded');


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getPageInfo') {
        const pageInfo = {
            url: window.location.href,
            title: document.title,
            hasForms: document.querySelectorAll('form').length > 0,
            hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
            hasLoginKeywords: /login|signin|sign-in|log-in|password|authenticate/i.test(document.body.innerText)
        };
        sendResponse(pageInfo);
    }
    return true;
});


document.addEventListener('submit', (e) => {
    const form = e.target;
    const hasPassword = form.querySelector('input[type="password"]');
    
    if (hasPassword) {
        console.log('PhishGuard: Password form submitted on', window.location.href);
        
   
        chrome.runtime.sendMessage({
            action: 'formSubmitted',
            url: window.location.href,
            hasPassword: true
        });
    }
});


function injectWarningBanner() {
    if (document.getElementById('phishguard-warning')) return;
    
    const banner = document.createElement('div');
    banner.id = 'phishguard-warning';
    banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: linear-gradient(135deg, #ff6b6b, #ee5a52);
        color: white;
        padding: 12px 20px;
        text-align: center;
        font-family: Arial, sans-serif;
        font-size: 14px;
        font-weight: bold;
        z-index: 999999;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
    `;
    
    banner.innerHTML = `
        <span>⚠️</span>
        <span>This page has been flagged as suspicious by PhishGuard</span>
        <button id="phishguard-dismiss" style="
            background: rgba(255,255,255,0.2);
            border: 1px solid rgba(255,255,255,0.3);
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 15px;
            font-size: 12px;
        ">Dismiss</button>
    `;
    
    document.body.prepend(banner);
    document.body.style.marginTop = '50px';
    
    
    banner.querySelector('#phishguard-dismiss').addEventListener('click', () => {
        banner.remove();
        document.body.style.marginTop = '';
    });
}


if (window.location.hostname.includes('phishing') || 
    window.location.hostname.includes('login-') ||
    window.location.hostname.includes('verify-') ||
    /login|signin|password|banking|paypal/i.test(window.location.href)) {
    
 
    chrome.runtime.sendMessage({
        action: 'checkPageSuspicious',
        url: window.location.href
    });
}