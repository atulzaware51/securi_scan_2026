<?php
// Ensure this script can only run via a local system terminal console execution path
if (php_sapi_name() !== 'cli') {
    die("Security Exception: This controller can only be executed via a Command Line Interface.\n");
}

require_once __DIR__ . '/config.php';

echo "==================================================\n";
echo "    SECURISCAN TERMINAL - DIRECT INGESTION CLI    \n";
echo "==================================================\n";

// Use standard input streams to collect interactive command line strings
echo "Enter the malicious URL target string: ";
$rawUrl = trim(fgets(STDIN));

if (empty($rawUrl)) {
    die("Execution Halted: Input string cannot be empty.\n");
}

echo "Select Category (1 for Phishing, 2 for Malware): ";
$choice = trim(fgets(STDIN));
$category = ($choice === '2') ? 'malware' : 'phishing';

// Cleanly isolate domain tokens
$urlForParsing = (!preg_match("~^(?:f|ht)tps?://~i", $rawUrl)) ? "http://" . $rawUrl : $rawUrl;
$parsedUrl = parse_url($urlForParsing);
$domain = isset($parsedUrl['host']) ? strtolower($parsedUrl['host']) : strtolower($rawUrl);
if (substr($domain, 0, 4) === 'www.') $domain = substr($domain, 4);

try {
    $conn = getDatabaseConnection();
    
    // System User ID 1 is designated as the system admin placeholder profile row
    $adminUserId = 1; 
    $status = 'approved'; // CLI bypasses moderation staging queues automatically

    $stmt = $conn->prepare("INSERT INTO url_submissions (user_id, url_submitted, threat_category, status) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("isss", $adminUserId, $rawUrl, $category, $status);
    
    if ($stmt->execute()) {
        echo "\n[SUCCESS] Direct insertion authorized! Target verified signature live.\n";
        echo "Domain: $domain\n";
        echo "Category: " . strtoupper($category) . "\n";
    }
    
    $stmt->close();
    $conn->close();
} catch (Throwable $e) {
    echo "\n[CRITICAL FAILURE] CLI write pipeline broke: " . $e->getMessage() . "\n";
}
echo "==================================================\n";
?>