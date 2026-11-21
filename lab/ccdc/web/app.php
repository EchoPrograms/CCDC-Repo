<?php
header('Content-Type: application/json');
if (file_exists('/tmp/site-offline')) { http_response_code(503); echo '{"error":"maintenance"}'; exit; }
try {
    $db = new PDO('mysql:host='.getenv('DB_HOST').';dbname='.getenv('DB_NAME').';charset=utf8mb4', getenv('DB_USER'), getenv('DB_PASSWORD'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 3]);
    $db->exec('CREATE TABLE IF NOT EXISTS visits (id BIGINT AUTO_INCREMENT PRIMARY KEY, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP)');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $db->beginTransaction();
        $db->exec('INSERT INTO visits () VALUES ()');
        $id = $db->lastInsertId();
        $db->commit();
        echo json_encode(['ok'=>true, 'visit_id'=>$id]);
    } else {
        $count = (int)$db->query('SELECT COUNT(*) FROM visits')->fetchColumn();
        echo json_encode(['ok'=>true, 'visits'=>$count]);
    }
} catch (Throwable $e) { http_response_code(503); echo '{"error":"database unavailable"}'; }
