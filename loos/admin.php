<?php
session_start();

// Strict Access Control Guardrail: Block unauthorized traffic
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
    header("Location: frontend/index.html");
    exit();
}

$host = "localhost";
$username = "root";
$password = "";
$dbname = "threat_db";
$conn = new mysqli($host, $username, $password, $dbname);

// 1. Fetch Global Telemetry Logs (Who entered which URL)
$globalLogs = $conn->query("SELECT s.*, u.username FROM scan_history s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.scanned_at DESC LIMIT 15");

// 2. Fetch Received Pending Database Submissions Queue
$pendingSubmissions = $conn->query("SELECT sub.*, u.username FROM url_submissions sub JOIN users u ON sub.user_id = u.id WHERE sub.status = 'pending' ORDER BY sub.submitted_at DESC");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecuriScan - Administrator Threat Deck</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
</head>
<body class="bg-light">

    <nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow mb-4">
        <div class="container">
            <span class="navbar-brand fw-bold text-danger"><i class="bi bi-cpu-fill me-2"></i>SecuriScan Admin Deck</span>
            <div class="ms-auto d-flex align-items-center">
                <span class="badge bg-danger me-3 text-uppercase">Systems Administrator</span>
                <a href="frontend/dashboard.html" class="btn btn-outline-light btn-sm me-2">User Workspace</a>
                <a href="../backend/logout.php" class="btn btn-sm btn-danger">Log Out</a>
            </div>
        </div>
    </nav>

    <main class="container">
        <div class="row mb-4">
            <div class="col-12">
                <h2 class="fw-bold text-dark">Database Control & Global Telemetry</h2>
                <p class="text-muted">Review real-time application traffic data or process incoming user database entry requests.</p>
            </div>
        </div>

        <div class="card border-0 shadow-sm p-4 bg-white mb-4">
            <h5 class="fw-bold mb-3 text-primary"><i class="bi bi-cloud-arrow-up-fill me-2"></i>Incoming Database Insertion Requests</h5>
            <div class="table-responsive">
                <table class="table table-hover align-middle small">
                    <thead class="table-light">
                        <tr>
                            <th>Submitted URL Target</th>
                            <th>Suggested Threat Category</th>
                            <th>Requesting User</th>
                            <th>Received Timestamp</th>
                            <th class="text-center">Database Actions Command</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if($pendingSubmissions->num_rows > 0): while($sub = $pendingSubmissions->fetch_assoc()): ?>
                        <tr id="row-submission-<?php echo $sub['id']; ?>">
                            <td class="fw-semibold"><code><?php echo htmlspecialchars($sub['url_submitted']); ?></code></td>
                            <td><span class="badge bg-secondary"><?php echo htmlspecialchars($sub['threat_category']); ?></span></td>
                            <td><strong><?php echo htmlspecialchars($sub['username']); ?></strong></td>
                            <td class="text-muted"><?php echo $sub['submitted_at']; ?></td>
                            <td class="text-center">
                                <button onclick="processRequest(<?php echo $sub['id']; ?>, 'approve')" class="btn btn-sm btn-success fw-bold me-1"><i class="bi bi-check-lg me-1"></i>Approve & Insert</button>
                                <button onclick="processRequest(<?php echo $sub['id']; ?>, 'reject')" class="btn btn-sm btn-outline-danger fw-bold"><i class="bi bi-trash-fill me-1"></i>Reject</button>
                            </td>
                        </tr>
                        <?php endwhile; else: ?>
                        <tr><td colspan="5" class="text-center text-muted py-3">No pending URL submission requests received.</td></tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="card border-0 shadow-sm p-4 bg-white mb-5">
            <h5 class="fw-bold mb-3 text-dark"><i class="bi bi-globe me-2"></i>Global Inspection Telemetry History</h5>
            <div class="table-responsive">
                <table class="table table-hover align-middle small mb-0">
                    <thead class="table-light text-muted">
                        <tr>
                            <th>Active Account Name</th>
                            <th>Inspected Target URL</th>
                            <th>Isolated Domain</th>
                            <th>System Verdict</th>
                            <th>Risk Score Metric</th>
                            <th>Execution Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while($log = $globalLogs->fetch_assoc()): 
                            $badge = $log['scan_verdict'] == 'safe' ? 'bg-success' : ($log['scan_verdict'] == 'malicious' ? 'bg-danger' : 'bg-warning text-dark');
                            $userDisplay = $log['username'] ? $log['username'] : 'Guest Session';
                        ?>
                        <tr>
                            <td><span class="fw-bold text-secondary"><i class="bi bi-person me-1"></i><?php echo htmlspecialchars($userDisplay); ?></span></td>
                            <td class="text-truncate" style="max-width: 250px;"><code><?php echo htmlspecialchars($log['url_scanned']); ?></code></td>
                            <td><code><?php echo htmlspecialchars($log['domain']); ?></code></td>
                            <td><span class="badge <?php echo $badge; ?> text-uppercase"><?php echo $log['scan_verdict']; ?></span></td>
                            <td class="fw-bold"><?php echo $log['risk_score']; ?>%</td>
                            <td class="text-muted"><?php echo $log['scanned_at']; ?></td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <script>
        // Asynchronous command routing execution loop
        async function processRequest(submissionId, actionCommand) {
            console.log(`[ADMIN_COMMAND_INIT] Dispatching execution data for Row: ${submissionId} | Action: ${actionCommand}`);
            
            const payload = new FormData();
            payload.append('id', submissionId);
            payload.append('action', actionCommand);

            try {
                const req = await fetch('../backend/admin_actions.php', { method: 'POST', body: payload });
                const res = await req.json();

                if (res.status === 'success') {
                    console.log(`[COMMAND_SUCCESS] Transaction executed. Dropping DOM tracking index row node.`);
                    document.getElementById(`row-submission-${submissionId}`).remove();
                } else {
                    alert("Execution dropped: " + res.message);
                }
            } catch (e) {
                alert("Internal Admin controller route connection failure.");
            }
        }
    </script>
</body>
</html>
<?php $conn->close(); ?>