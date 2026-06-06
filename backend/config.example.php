<?php
// backend/config.example.php
// INSTRUCTIONS: Rename this file to config.php and update your credentials

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

function getDatabaseConnection() {
    $host = "127.0.0.1"; 
    $username = "root";       // Change to your MySQL username
    $password = "";           // Change to your MySQL password
    $dbname = "threat_db";    // Ensure this database is created in phpMyAdmin

    try {
        $conn = mysqli_init();
        $conn->options(MYSQLI_OPT_CONNECT_TIMEOUT, 3);
        $conn->real_connect($host, $username, $password, $dbname);
        return $conn;
    } catch (Exception $e) {
        header('Content-Type: application/json');
        echo json_encode(["status" => "error", "message" => "Database link failure."]);
        exit();
    }
}
?>