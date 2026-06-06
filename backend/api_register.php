<?php
// backend/api_register.php

ob_start();
session_start();
require_once 'config.php';

ob_clean();
header('Content-Type: application/json');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception("Invalid request method.");
    }

    $conn = getDatabaseConnection();
    
    $user = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $pass = trim($_POST['password'] ?? '');
    
    if (empty($user) || empty($email) || empty($pass)) {
        echo json_encode(["status" => "error", "message" => "All fields are required."]);
        exit();
    }
    
    $hash = password_hash($pass, PASSWORD_BCRYPT);
    
    $stmt = $conn->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $user, $email, $hash);
    
    if ($stmt->execute()) {
        echo json_encode(["status" => "success", "message" => "Account provisioned successfully."]);
    } else {
        throw new Exception("Insert failed.");
    }
    
    $stmt->close();
    $conn->close();

} catch (mysqli_sql_exception $e) {
    // Code 1062 is MySQL's specific error for a Duplicate Entry (Unique constraint)
    if ($e->getCode() == 1062) {
        echo json_encode(["status" => "error", "message" => "Username or Email is already taken."]);
    } else {
        echo json_encode(["status" => "error", "message" => "Database Error: " . $e->getMessage()]);
    }
} catch (Throwable $e) {
    echo json_encode(["status" => "error", "message" => "System Fault: " . $e->getMessage()]);
}
?>