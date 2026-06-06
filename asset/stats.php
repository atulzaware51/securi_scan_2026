<?php
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(["error" => "Unauthorized access"]);
    exit();
}

$host = "localhost";
$username = "root";
$password = "";
$dbname = "threat_db";

$conn = new mysqli($host, $username, $password, $dbname);
$currentUserId = $_SESSION['user_id'];
// $userRole = $_SESSION['role'];
$userRole = isset($_SESSION['role']) ? $_SESSION['role'] : 'user';
// Role-Based Isolation Layer
if ($userRole === 'admin') {
    // Admins see system-wide metrics
    $totalScans = $conn->query("SELECT COUNT(*) as total FROM scan_history")->fetch_assoc()['total'];
    $totalThreats = $conn->query("SELECT COUNT(*) as total FROM scan_history WHERE scan_verdict IN ('malicious', 'warning')")->fetch_assoc()['total'];
    $historyResult = $conn->query("SELECT url_scanned, scan_verdict, risk_score, scanned_at FROM scan_history ORDER BY scanned_at DESC LIMIT 5");
} else {
    // Standard clients only pull individual analytics records
    $stmt1 = $conn->prepare("SELECT COUNT(*) as total FROM scan_history WHERE user_id = ?");
    $stmt1->bind_param("i", $currentUserId);
    $stmt1->execute();
    $totalScans = $stmt1->get_result()->fetch_assoc()['total'];

    $stmt2 = $conn->prepare("SELECT COUNT(*) as total FROM scan_history WHERE user_id = ? AND scan_verdict IN ('malicious', 'warning')");
    $stmt2->bind_param("i", $currentUserId);
    $stmt2->execute();
    $totalThreats = $stmt2->get_result()->fetch_assoc()['total'];

    $historyResult = $conn->prepare("SELECT url_scanned, scan_verdict, risk_score, scanned_at FROM scan_history WHERE user_id = ? ORDER BY scanned_at DESC LIMIT 5");
    $historyResult->bind_param("i", $currentUserId);
    $historyResult->execute();
    $historyResult = $historyResult->get_result();
}

$recentScans = [];
while ($row = $historyResult->fetch_assoc()) {
    $recentScans[] = $row;
}

echo json_encode([
    "stats" => [
        "total_scans" => $totalScans,
        "threats_detected" => $totalThreats
    ],
    "recent_scans" => $recentScans
]);
$conn->close();
?>