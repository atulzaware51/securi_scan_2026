<?php
// backend/api_login.php

// Prevent any stray spaces or HTML from breaking the JSON output
ob_start(); 
session_start();

require_once 'config.php';

// Wipe the buffer and set strict JSON headers
ob_clean();
header('Content-Type: application/json');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception("Invalid request method.");
    }

    $conn = getDatabaseConnection();
    
    $user = trim($_POST['username'] ?? '');
    $pass = trim($_POST['password'] ?? '');
    
    if(empty($user) || empty($pass)) {
        echo json_encode(["status" => "error", "message" => "Credentials cannot be empty."]);
        exit();
    }
    
    $stmt = $conn->prepare("SELECT id, password_hash, role FROM users WHERE username = ?");
    $stmt->bind_param("s", $user);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        
        if (password_verify($pass, $row['password_hash'])) {
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $user;
            $_SESSION['role'] = $row['role'];
            
            // Instantly unlock the session file so subsequent API calls don't hang
            session_write_close();
            
            echo json_encode([
                "status" => "success", 
                "role" => $row['role'],
                "message" => "Authentication verified."
            ]);
        } else {
            echo json_encode(["status" => "error", "message" => "Invalid credentials."]);
        }
    } else {
        echo json_encode(["status" => "error", "message" => "Invalid credentials."]);
    }
    
    $stmt->close();
    $conn->close();

} catch (Throwable $e) {
    echo json_encode([
        "status" => "error", 
        "message" => "Server Error: " . $e->getMessage()
    ]);
}
?>