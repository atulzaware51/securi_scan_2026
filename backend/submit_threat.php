<?php
// backend/submit_threat.php

ob_start();
session_start();
require_once 'config.php';

ob_clean();
header('Content-Type: application/json');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception("Invalid request method.");
    }

    if (!isset($_SESSION['user_id'])) {
        echo json_encode(["status" => "error", "message" => "Authentication required to submit threats."]);
        exit();
    }

    $conn = getDatabaseConnection();
    $userId = $_SESSION['user_id'];
    $url = trim($_POST['url'] ?? '');
    $category = trim($_POST['category'] ?? '');

    if (empty($url) || empty($category)) {
        echo json_encode(["status" => "error", "message" => "Target URL and Category are required."]);
        exit();
    }

    $stmt = $conn->prepare("INSERT INTO url_submissions (user_id, url_submitted, threat_category) VALUES (?, ?, ?)");
    $stmt->bind_param("iss", $userId, $url, $category);
    
    if ($stmt->execute()) {
        echo json_encode(["status" => "success", "message" => "Threat successfully logged for administrator review."]);
    } else {
        throw new Exception("Database insertion failed.");
    }

    $stmt->close();
    $conn->close();

} catch (Throwable $e) {
    echo json_encode(["status" => "error", "message" => "Submission Error: " . $e->getMessage()]);
}
?>