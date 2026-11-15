<?php
// Intentionally vulnerable native-PHP script (academic SAST target).
// Each VULN line below is a true positive; the SAFE lines must not be flagged.

$conn = mysqli_connect("127.0.0.1", "root", "", "app");

$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;      // tainted SQL built here
$res = mysqli_query($conn, $query);                    // VULN: SQL injection

echo "Hello " . $_GET['name'];                         // VULN: reflected XSS

system("ping -c1 " . $_GET['host']);                   // VULN: command injection

include $_GET['page'] . ".php";                        // VULN: file inclusion

eval($_POST['code']);                                  // VULN: code injection

// ---- safe counterparts (must produce no findings) ----
$safe_id = intval($_GET['id']);
$q2 = "SELECT * FROM users WHERE id = " . $safe_id;    // sanitized -> safe
$res2 = mysqli_query($conn, $q2);

echo htmlspecialchars($_GET['name']);                  // encoded -> safe

$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?"); // parameterized -> safe
