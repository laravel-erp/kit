<?php
declare(strict_types=1);
require __DIR__ . '/../src/Runtime/RegionCatalog.php';
use LaravelErp\Bridge\Runtime\RegionCatalog;
$rc = new RegionCatalog($argv[1] ?? 'x', $argv[2] ?? 'y');
$override = ($argv[3] ?? '') !== '' ? $argv[3] : null;
$rc->halt($override);
echo "NOHALT\n";