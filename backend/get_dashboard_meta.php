<?php
// backend/get_dashboard_meta.php

ob_start();
session_start();
require_once 'config.php';

ob_clean();
header('Content-Type: application/json');

try {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(["status" => "unauthorized"]);
        exit();
    }

    $conn = getDatabaseConnection();
    $userId = $_SESSION['user_id'];

    $responseData = [
        "status" => "success",
        "username" => $_SESSION['username'] ?? 'User',
        "role" => $_SESSION['role'] ?? 'user',
        "metrics" => ["totalScans" => 0, "maliciousScans" => 0, "warningScans" => 0],
        "notifications" => [],
        "history" => []
    ];

    // 1. Fetch Metrics
    $stmt1 = $conn->query("SELECT COUNT(*) as cnt FROM scan_history WHERE user_id = $userId");
    $responseData["metrics"]["totalScans"] = $stmt1->fetch_assoc()['cnt'];

    $stmt2 = $conn->query("SELECT COUNT(*) as cnt FROM scan_history WHERE user_id = $userId AND scan_verdict = 'malicious'");
    $responseData["metrics"]["maliciousScans"] = $stmt2->fetch_assoc()['cnt'];

    $stmt3 = $conn->query("SELECT COUNT(*) as cnt FROM scan_history WHERE user_id = $userId AND scan_verdict IN ('warning', 'suspicious')");
    $responseData["metrics"]["warningScans"] = $stmt3->fetch_assoc()['cnt'];

    // 2. Fetch Notifications
    $notifQ = $conn->query("SELECT url_submitted, status, submitted_at FROM url_submissions WHERE user_id = $userId ORDER BY submitted_at DESC LIMIT 5");
    while($notif = $notifQ->fetch_assoc()) {
        $responseData["notifications"][] = $notif;
    }

    // 3. Fetch History
    $histQ = $conn->query("SELECT url_scanned, domain, scan_verdict, risk_score, scanned_at FROM scan_history WHERE user_id = $userId ORDER BY scanned_at DESC LIMIT 5");
    while($row = $histQ->fetch_assoc()) {
        $responseData["history"][] = $row;
    }

    echo json_encode($responseData);
    $conn->close();

} catch (Throwable $e) {
    echo json_encode(["status" => "error", "message" => "Dashboard API Error: " . $e->getMessage()]);
}
?>