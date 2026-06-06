<?php
// backend/api_admin_data.php

ob_start();
session_start();
require_once 'config.php';

ob_clean();
header('Content-Type: application/json');

try {
    // Strict RBAC Guard
    if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
        echo json_encode(["status" => "unauthorized"]);
        exit();
    }

    $conn = getDatabaseConnection();
    $responseData = ["status" => "success", "pending_submissions" => [], "global_logs" => []];

    // Fetch Pending Approvals
    $pendingQ = $conn->query("SELECT sub.id, sub.url_submitted, sub.threat_category, sub.submitted_at, u.username FROM url_submissions sub JOIN users u ON sub.user_id = u.id WHERE sub.status = 'pending' ORDER BY sub.submitted_at DESC");
    while($row = $pendingQ->fetch_assoc()) {
        $responseData["pending_submissions"][] = $row;
    }

    // Fetch Global Scans
    $logsQ = $conn->query("SELECT s.url_scanned, s.domain, s.scan_verdict, s.risk_score, s.scanned_at, u.username FROM scan_history s LEFT JOIN users u ON s.user_id = u.id ORDER BY s.scanned_at DESC LIMIT 20");
    while($row = $logsQ->fetch_assoc()) {
        $responseData["global_logs"][] = $row;
    }

    echo json_encode($responseData);
    $conn->close();

} catch (Throwable $e) {
    echo json_encode(["status" => "error", "message" => "Admin Fetch Error: " . $e->getMessage()]);
}
?>