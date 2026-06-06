// frontend/js/dashboard.js

document.addEventListener('DOMContentLoaded', async () => {
    await initializeDashboardMetadata();

    const scanBtn = document.getElementById('dashboardScanBtn');
    if (scanBtn) scanBtn.addEventListener('click', executeTargetInspectionAnalysis);

    const submitForm = document.getElementById('threatSubmitForm');
    if (submitForm) submitForm.addEventListener('submit', executeThreatSubmission);
});

// --- FETCH DASHBOARD DATA ---
async function initializeDashboardMetadata() {
    try {
        const req = await fetch('../backend/get_dashboard_meta.php');
        const data = await req.json();

        if (data.status === 'unauthorized') {
            window.location.href = 'index.html';
            return;
        }

        // Render Metrics
        document.getElementById('navProfileName').innerText = `${data.username} (${data.role})`;
        document.getElementById('navTotalScans').innerText = data.metrics.totalScans;
        document.getElementById('navThreatScans').innerText = data.metrics.maliciousScans;
        document.getElementById('cardTotalScans').innerText = data.metrics.totalScans;
        document.getElementById('cardMaliciousScans').innerText = data.metrics.maliciousScans;
        document.getElementById('cardWarningScans').innerText = data.metrics.warningScans;

        // Render Notifications
        const notifContainer = document.getElementById('notificationDropdownContainer');
        notifContainer.innerHTML = '<h6 class="dropdown-header text-dark fw-bold border-bottom pb-2 mb-2">My Submissions</h6>'; 
        
        if (data.notifications && data.notifications.length > 0) {
            document.getElementById('notificationBadge').classList.remove('d-none');
            data.notifications.forEach(notif => {
                let icon = '<i class="bi bi-clock-fill text-warning"></i>';
                if (notif.status === 'approved') icon = '<i class="bi bi-check-circle-fill text-success"></i>';
                if (notif.status === 'rejected') icon = '<i class="bi bi-x-circle-fill text-danger"></i>';
                
                const li = document.createElement('li');
                li.className = "dropdown-item small text-wrap border-bottom pb-2 mb-2";
                li.innerHTML = `${icon} <strong>${notif.url_submitted}</strong><br><span class="text-muted">Status: ${notif.status.toUpperCase()}</span>`;
                notifContainer.appendChild(li);
            });
        } else {
            document.getElementById('notificationBadge').classList.add('d-none');
            notifContainer.innerHTML += '<li class="dropdown-item small text-muted">No pending requests.</li>';
        }

        // Render History Table
        const tableBody = document.getElementById('historyTableBody');
        tableBody.innerHTML = ''; 
        if (data.history && data.history.length > 0) {
            data.history.forEach(row => {
                const badgeColor = row.scan_verdict === 'safe' ? 'bg-success' : (row.scan_verdict === 'malicious' ? 'bg-danger' : 'bg-warning text-dark');
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="text-truncate fw-semibold" style="max-width: 250px;">${row.url_scanned}</td>
                    <td><code>${row.domain}</code></td>
                    <td><span class="badge ${badgeColor} text-uppercase px-2 py-1">${row.scan_verdict}</span></td>
                    <td class="fw-bold">${row.risk_score}%</td>
                    <td class="text-muted">${row.scanned_at}</td>
                `;
                tableBody.appendChild(tr);
            });
        } else {
            tableBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No account inspection logs found.</td></tr>';
        }
    } catch (err) {
        console.error("Metadata fetch failed.", err);
    }
}

// --- SILENT URL SCANNER (No Interrupting Popups) ---
async function executeTargetInspectionAnalysis() {
    const inputVal = document.getElementById('dashboardUrlInput').value;
    if (!inputVal) return;

    const btn = document.getElementById('dashboardScanBtn');
    const resultCard = document.getElementById('dashboardResultCard');
    const resultContent = document.getElementById('dashboardResultContent');

    btn.innerText = "Analyzing...";
    btn.disabled = true;
    resultCard.classList.add('d-none');

    try {
        const payload = new FormData();
        payload.append('url', inputVal);

        const req = await fetch('../backend/scan.php', { method: 'POST', body: payload });
        const res = await req.json();

        if (res.status === 'error') {
            alert(res.reasons[0]);
            btn.innerText = "Analyze Target";
            btn.disabled = false;
            return;
        }

        // Output the results quietly
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

        await initializeDashboardMetadata();

        // THE AUTO-POPUP CODE HAS BEEN COMPLETELY DELETED HERE!

    } catch (e) {
        console.error("Scan error.", e);
        alert("API connection failure.");
    }
    
    btn.innerText = "Analyze Target";
    btn.disabled = false;
}

// --- MANUAL THREAT SUBMISSION LOGIC ---
async function executeThreatSubmission(e) {
    e.preventDefault(); 
    
    const btn = document.getElementById('submitConfirmBtn');
    const alertBox = document.getElementById('submitAlert');
    const url = document.getElementById('submitUrl').value;
    const category = document.getElementById('submitCategory').value;

    btn.innerText = "Sending to Admin..."; 
    btn.disabled = true;

    const formData = new FormData();
    formData.append('url', url);
    formData.append('category', category);

    try {
        const response = await fetch('../backend/submit_threat.php', { method: 'POST', body: formData });
        const data = await response.json();

        alertBox.classList.remove('d-none', 'alert-success', 'alert-danger');
        alertBox.classList.add(data.status === 'success' ? 'alert-success' : 'alert-danger');
        alertBox.innerText = data.message;
        
        if (data.status === 'success') {
            document.getElementById('submitUrl').value = ''; // Clear form
            await initializeDashboardMetadata(); // Refresh notification bell
            
            setTimeout(() => {
                var modal = bootstrap.Modal.getInstance(document.getElementById('submitThreatModal'));
                if(modal) modal.hide();
                alertBox.classList.add('d-none');
            }, 2000); 
        }
    } catch (err) {
        alertBox.classList.remove('d-none'); 
        alertBox.classList.add('alert-danger');
        alertBox.innerText = "Connection error. Try again.";
    }
    
    btn.innerText = "Send to Admin for Approval"; 
    btn.disabled = false;
}