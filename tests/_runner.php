<?php
declare(strict_types=1);
require __DIR__ . '/../src/Runtime/RegionCatalog.php';
use LaravelErp\Bridge\Runtime\RegionCatalog;
$baseDir = $argv[1] ?? '';
$origin = $argv[2] ?? '';
(new RegionCatalog($baseDir, $origin))->evaluate();
echo "PASS\n";