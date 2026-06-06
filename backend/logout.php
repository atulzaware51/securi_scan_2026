<?php
// backend/logout.php

session_start();
session_unset();
session_destroy();
// Completely wipe the browser's session cookie
setcookie(session_name(), '', time() - 3600, '/'); 

header("Location: ../frontend/index.html");
exit();
?>