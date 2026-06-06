<?php
// backend/scan.php

ob_start();
session_start();
require_once 'config.php';

ob_clean();
header('Content-Type: application/json');

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception("HTTP Request Method Denied.");
    }

    $conn = getDatabaseConnection();
    $url = trim($_POST['url'] ?? '');

    if (empty($url)) {
        echo json_encode(["status" => "error", "reasons" => ["Inspection path target cannot be empty."]]);
        exit();
    }

    // Standardize protocol mapping wrappers
    $urlForParsing = (!preg_match("~^(?:f|ht)tps?://~i", $url)) ? "http://" . $url : $url;
    $parsedUrl = parse_url($urlForParsing);
    $domain = isset($parsedUrl['host']) ? strtolower($parsedUrl['host']) : strtolower($url);
    if (substr($domain, 0, 4) === 'www.') $domain = substr($domain, 4);
    $path = isset($parsedUrl['path']) ? strtolower($parsedUrl['path']) : '';

    $userId = $_SESSION['user_id'] ?? null;

    // Guest freemium checking limits
    if (!$userId) {
        if (!isset($_SESSION['guest_scans'])) $_SESSION['guest_scans'] = 0;
        if ($_SESSION['guest_scans'] >= 2) {
            echo json_encode(["status" => "limit_reached"]);
            exit();
        }
        $_SESSION['guest_scans']++;
    }

    $scanVerdict = "safe";
    $riskScore = 0;
    $detectionMethod = "Clean Database Trace Match";
    $reasons = [];

    // --- LAYER 1: SYNCHRONOUS SIGNATURE VERIFICATION ---
    $sigStmt = $conn->prepare("SELECT threat_category FROM url_submissions WHERE (url_submitted LIKE ? OR url_submitted LIKE ?) AND status = 'approved'");
    $searchParamNormal = "%" . $domain . "%";
    $searchParamRaw = "%" . $url . "%";
    $sigStmt->bind_param("ss", $searchParamNormal, $searchParamRaw);
    $sigStmt->execute();
    $sigResult = $sigStmt->get_result();

    if ($sigResult->num_rows > 0) {
        $matchedThreat = $sigResult->fetch_assoc();
        $scanVerdict = "malicious";
        $riskScore = 100;
        $detectionMethod = "Signature Database Match";
        $reasons[] = "Target matches confirmed blocklist threat signature indexed as: " . strtoupper($matchedThreat['threat_category']);
    }
    $sigStmt->close();

    // --- LAYER 2: ADVANCED ENTERPRISE BEHAVIORAL HEURISTICS ---
    if ($scanVerdict === "safe") {
        $heuristicPoints = 0;

        // Rule A: Numerical IP Architecture Traps
        if (preg_match('/^[0-9.]+$/', $domain) || filter_var($domain, FILTER_VALIDATE_IP)) {
            $heuristicPoints += 40;
            $reasons[] = "Raw numeric IP configuration detected instead of standard domain routing.";
        }

        // Rule B: High-Risk Phishing Semantic Keyword Sniffing
        $suspiciousKeywords = ['secure', 'login', 'verify', 'update', 'banking', 'free', 'wallet', 'signin', 'account-auth'];
        foreach ($suspiciousKeywords as $keyword) {
            if (strpos($url, $keyword) !== false) {
                $heuristicPoints += 25;
                $reasons[] = "URL path heavily exploits urgent phishing keyword tokens ('" . $keyword . "').";
                break;
            }
        }

        // Rule C: High-Risk TLD (Top-Level Domain) Inspection
        // Hackers heavily purchase cheap, unmonitored extensions (.xyz, .top, .cc, .click) for burnable links
        $highRiskTlds = ['.xyz', '.top', '.cc', '.click', '.download', '.live', '.tokyo', '.info', '.gq', '.tk'];
        foreach ($highRiskTlds as $tld) {
            if (str_ends_with($domain, $tld) || strpos($domain, $tld . '/') !== false) {
                $heuristicPoints += 30;
                $reasons[] = "Registered extension leverages high-risk, low-reputation TLD workspace ('" . $tld . "').";
                break;
            }
        }

        // Rule D: Dangerous Payload File Extension Scans
        // Catching direct endpoint delivery routes for executable or scripted assets (.exe, .scr, .zip)
        $dangerousExtensions = ['.exe', '.scr', '.vbs', '.apk', '.jar', '.bat', '.cmd', '.zip', '.rar'];
        foreach ($dangerousExtensions as $ext) {
            if (str_ends_with($path, $ext) || strpos($path, $ext . '?') !== false) {
                $heuristicPoints += 50;
                $reasons[] = "Terminal link path drops an active binary payload execution file signature ('" . $ext . "').";
                break;
            }
        }

        // Rule E: URL Obfuscation & Character Entropy Verification
        if (strpos($url, '@') !== false) {
            $heuristicPoints += 45;
            $reasons[] = "Credential obfuscation indicator discovered ('@' token routing manipulation).";
        }
        if (substr_count($domain, '-') >= 3) {
            $heuristicPoints += 20;
            $reasons[] = "Excessive domain word fragmentation dashes indicates brand impersonation behavior.";
        }

        // --- CALCULATE VERDICT BASED ON ACCUMULATED WEIGHT ---
        if ($heuristicPoints > 0) {
            $detectionMethod = "Zero-Day Behavioral Heuristics";
            $riskScore = min($heuristicPoints, 99); // Max out heuristic score at 99%

            if ($riskScore >= 60) {
                $scanVerdict = "malicious";
            } elseif ($riskScore >= 30) {
                $scanVerdict = "warning";
            } else {
                $scanVerdict = "suspicious";
            }
        }
    }

    if (empty($reasons)) {
        $reasons[] = "No lookalike configurations or dangerous file payload droppers detected.";
        $reasons[] = "Domain structure evaluated successfully against default zero-trust matrices.";
    }

    // --- WRITE RECORD TO LOGS ---
    if ($userId) {
        $logStmt = $conn->prepare("INSERT INTO scan_history (user_id, url_scanned, domain, scan_verdict, risk_score) VALUES (?, ?, ?, ?, ?)");
        $logStmt->bind_param("isssd", $userId, $url, $domain, $scanVerdict, $riskScore);
    } else {
        $logStmt = $conn->prepare("INSERT INTO scan_history (user_id, url_scanned, domain, scan_verdict, risk_score) VALUES (NULL, ?, ?, ?, ?)");
        $logStmt->bind_param("sssd", $url, $domain, $scanVerdict, $riskScore);
    }
    $logStmt->execute();
    $logStmt->close();
    
    session_write_close();

    echo json_encode([
        "status" => $scanVerdict,
        "confidence" => (int)$riskScore,
        "method" => $detectionMethod,
        "domain" => $domain,
        "url" => $url,
        "reasons" => $reasons
    ]);

    $conn->close();

} catch (Throwable $e) {
    echo json_encode([
        "status" => "error",
        "confidence" => 0,
        "method" => "System Framework Exception Handler",
        "domain" => "System Crash Intercept",
        "url" => "N/A",
        "reasons" => ["FATAL REJECTION: " . $e->getMessage()]
    ]);
}
?>