<?php
// Deliberately exposed maintenance endpoint in an isolated training container.
header('Content-Type: text/plain');
$actions = ['identity' => 'id', 'processes' => 'ps aux', 'uptime' => 'uptime'];
$action = $_GET['action'] ?? '';
if (!isset($actions[$action])) { http_response_code(400); echo "Choose identity, processes, or uptime\n"; exit; }
system($actions[$action]);
