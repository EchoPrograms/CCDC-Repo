<?php
header('Content-Type: text/plain');
$actions = ['identity' => 'id', 'processes' => 'ps aux', 'uptime' => 'uptime'];
$action = $_GET['action'] ?? '';
if (!isset($actions[$action])) { http_response_code(400); exit('Choose identity, processes, or uptime'); }
system($actions[$action]);
