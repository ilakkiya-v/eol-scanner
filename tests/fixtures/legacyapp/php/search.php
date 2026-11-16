<?php
// legacy search page (test fixture: intentionally vulnerable patterns)
$q = $_GET['q'];
$res = mysqli_query($conn, "SELECT * FROM items WHERE name LIKE '%$q%'");
echo $_GET['q'];
include($_GET['page'] . ".php");
system("ping -c 1 " . $_GET['host']);
header("Location: " . $_GET['next']);
$x = file_get_contents($_GET['url']);
