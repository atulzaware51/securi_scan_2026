// frontend/js/public_dashboard.js

document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('publicScanBtn');
    if (scanBtn) {
        scanBtn.addEventListener('click', executePublicScan);
    }
});

async function executePublicScan() {
    const inputVal = document.getElementById('publicUrlInput').value;
    if (!inputVal) return;

    const btn = document.getElementById('publicScanBtn');
    const resultCard = document.getElementById('publicResultCard');
    const resultContent = document.getElementById('publicResultContent');

    btn.innerText = "Analyzing...";
    btn.disabled = true;
    resultCard.classList.add('d-none');

    try {
        const payload = new FormData();
        payload.append('url', inputVal);

        const req = await fetch('../backend/scan.php', { method: 'POST', body: payload });
        const res = await req.json();

        // Check Freemium Limit
        if (res.status === 'limit_reached') {
            const loginWallBody = document.querySelector('#loginWallModal .modal-body');
            loginWallBody.innerHTML = `
                <h3 class="fw-bold text-dark mb-3"><i class="bi bi-shield-lock-fill text-primary"></i> Access Restricted</h3>
                <p class="text-muted mb-4">You have exhausted your free guest inspection allocations.</p>
                <div class="d-flex gap-2">
                    <button type="button" class="btn btn-outline-secondary w-50" data-bs-dismiss="modal">Close</button>
                    <a href="register.html" class="btn btn-primary w-50 fw-bold">Sign Up Free</a>
                </div>
            `;
            var limitModal = new bootstrap.Modal(document.getElementById('loginWallModal'));
            limitModal.show();
            
            btn.innerText = "Analyze Target";
            btn.disabled = false;
            return;
        }

        if (res.status === 'error') {
            alert(res.reasons[0]);
            btn.innerText = "Analyze Target";
            btn.disabled = false;
            return;
        }

        // Render Scan Results Quietly
        resultCard.classList.remove('d-none');
        let statusColor = res.status === 'safe' ? 'border-success' : (res.status === 'malicious' ? 'border-danger' : 'border-warning');
        resultCard.className = `card mt-4 shadow-sm border-0 border-start border-4 ${statusColor}`;
        
        let bulletPoints = res.reasons.map(pt => `<li class="mb-1">${pt}</li>`).join('');

        resultContent.innerHTML = `
            <div class="d-flex align-items-center justify-content-between mb-2">
                <h4 class="fw-bold mb-0 text-uppercase">Analysis Outcome: ${res.status}</h4>
                <span class="fs-4 fw-bold">${res.confidence}% Risk Score</span>
            </div>
            <p class="mb-3 opacity-75"><strong>Method:</strong> ${res.method} | <strong>Domain:</strong> <code>${res.domain}</code></p>
            <hr class="my-2 opacity-25">
            <ul class="mb-0 ps-3 small">${bulletPoints}</ul>
        `;

        // THE AUTO-POPUP CODE HAS BEEN COMPLETELY DELETED HERE!

    } catch (e) {
        console.error("Public scan engine fault.", e);
        alert("API connection failure.");
    }
    
    btn.innerText = "Analyze Target";
    btn.disabled = false;
}