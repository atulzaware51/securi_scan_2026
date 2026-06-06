// frontend/js/admin.js

document.addEventListener('DOMContentLoaded', async () => {
    await fetchAdminData();
});

async function fetchAdminData() {
    try {
        const req = await fetch('../backend/api_admin_data.php');
        const data = await req.json();

        // Security Bounce: Boot non-admins out
        if (data.status === 'unauthorized' || data.status === 'error') {
            alert("Unauthorized: " + (data.message || "Admin clearance required."));
            window.location.href = 'dashboard.html';
            return;
        }

        // Render Pending Approval Queue
        const pendingTable = document.getElementById('adminPendingTable');
        pendingTable.innerHTML = ''; 
        
        if (data.pending_submissions && data.pending_submissions.length > 0) {
            data.pending_submissions.forEach(sub => {
                const tr = document.createElement('tr');
                tr.id = `row-submission-${sub.id}`;
                tr.innerHTML = `
                    <td class="fw-semibold text-primary"><code>${sub.url_submitted}</code></td>
                    <td><span class="badge bg-secondary text-uppercase">${sub.threat_category}</span></td>
                    <td><strong>${sub.username}</strong></td>
                    <td class="text-muted small">${sub.submitted_at}</td>
                    <td class="text-center">
                        <button onclick="processRequest(${sub.id}, 'approve')" class="btn btn-sm btn-success fw-bold shadow-sm me-2">Approve</button>
                        <button onclick="processRequest(${sub.id}, 'reject')" class="btn btn-sm btn-outline-danger fw-bold shadow-sm">Reject</button>
                    </td>
                `;
                pendingTable.appendChild(tr);
            });
        } else {
            pendingTable.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">No pending URL submissions.</td></tr>';
        }

        // Render Global Platform History
        const logsTable = document.getElementById('adminLogsTable');
        logsTable.innerHTML = ''; 
        
        if (data.global_logs && data.global_logs.length > 0) {
            data.global_logs.forEach(log => {
                const userDisplay = log.username ? log.username : 'Guest Session';
                const badge = log.scan_verdict === 'safe' ? 'bg-success' : (log.scan_verdict === 'malicious' ? 'bg-danger' : 'bg-warning text-dark');
                
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><span class="fw-bold text-secondary"><i class="bi bi-person-fill me-1"></i>${userDisplay}</span></td>
                    <td class="text-truncate" style="max-width: 250px;"><code>${log.url_scanned}</code></td>
                    <td><span class="badge ${badge} text-uppercase px-2 py-1">${log.scan_verdict}</span></td>
                    <td class="fw-bold">${log.risk_score}%</td>
                    <td class="text-muted small">${log.scanned_at}</td>
                `;
                logsTable.appendChild(tr);
            });
        } else {
            logsTable.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">No system history logs found.</td></tr>';
        }

    } catch (e) {
        console.error("Admin telemetry fetch failed.", e);
        alert("Failed to load admin deck. Check console.");
    }
}

// Global scope function so HTML buttons can click it
window.processRequest = async function(submissionId, actionCommand) {
    // Visual feedback
    const row = document.getElementById(`row-submission-${submissionId}`);
    row.style.opacity = '0.5';

    const payload = new FormData();
    payload.append('id', submissionId);
    payload.append('action', actionCommand);

    try {
        const req = await fetch('../backend/admin_actions.php', { method: 'POST', body: payload });
        const res = await req.json();

        if (res.status === 'success') {
            // Remove the row instantly from the screen
            row.remove();
            alert(`URL successfully ${actionCommand}d! It is now live in the database.`);
        } else {
            row.style.opacity = '1';
            alert("Database Error: " + res.message);
        }
    } catch (e) {
        row.style.opacity = '1';
        alert("Fatal connection error modifying database entry.");
    }
};