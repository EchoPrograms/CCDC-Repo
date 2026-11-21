<?php
header('Content-Type: application/json');
if (file_exists('/var/lib/ccdc-practice/offline')) { http_response_code(503); echo '{"error":"maintenance"}'; exit; }
$f = fopen('/var/lib/ccdc-practice/visits', 'c+');
if (!$f || !flock($f, LOCK_EX)) { http_response_code(503); echo '{"error":"storage"}'; exit; }
$n = (int)stream_get_contents($f);
if ($_SERVER['REQUEST_METHOD'] === 'POST') { $n++; rewind($f); ftruncate($f, 0); fwrite($f, (string)$n); fflush($f); }
flock($f, LOCK_UN); fclose($f); echo json_encode(['ok'=>true,'visits'=>$n]);
