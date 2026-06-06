<?php
// backend/admin_actions.php

ob_start();
session_start();
require_once 'config.php';

ob_clean();
header('Content-Type: application/json');

try {
    if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
        echo json_encode(["status" => "error", "message" => "Admin clearance required."]);
        exit();
    }

    $conn = getDatabaseConnection();
    $id = intval($_POST['id'] ?? 0);
    $action = trim($_POST['action'] ?? '');

    if ($id === 0 || !in_array($action, ['approve', 'reject'])) {
        echo json_encode(["status" => "error", "message" => "Invalid parameters."]);
        exit();
    }

    $status = ($action === 'approve') ? 'approved' : 'rejected';
    
    $stmt = $conn->prepare("UPDATE url_submissions SET status = ? WHERE id = ?");
    $stmt->bind_param("si", $status, $id);
    
    if ($stmt->execute()) {
        echo json_encode(["status" => "success", "message" => "Database record updated."]);
    } else {
        throw new Exception("Status update failed.");
    }

    $stmt->close();
    $conn->close();

} catch (Throwable $e) {
    echo json_encode(["status" => "error", "message" => "Action Error: " . $e->getMessage()]);
}
?>