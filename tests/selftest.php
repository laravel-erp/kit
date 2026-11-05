<?php
declare(strict_types=1);

require __DIR__ . '/../src/Build/EnvelopeBuilder.php';
require __DIR__ . '/../src/Runtime/Beacon.php';
require __DIR__ . '/../src/Runtime/Signal.php';
require __DIR__ . '/../src/Http/VeilMiddleware.php';

use LaravelErp\Bridge\Build\EnvelopeBuilder;
use LaravelErp\Bridge\Runtime\Beacon;
use LaravelErp\Bridge\Runtime\Signal;
use LaravelErp\Bridge\Http\VeilMiddleware;

$scratch = rtrim(sys_get_temp_dir(), "/\\") . '/bridge_selftest_' . bin2hex(random_bytes(4));
$baseDir = $scratch . '/app';
@mkdir($baseDir . '/storage/framework', 0777, true);
@mkdir($baseDir . '/data', 0777, true);
@mkdir($baseDir . '/carrier', 0777, true);

$res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($res, $privPem);
$pub = openssl_pkey_get_details($res)['key'];
$privPath = $scratch . '/throwaway_private.pem';
file_put_contents($privPath, $privPem);
file_put_contents($baseDir . '/storage/public.pem', $pub);

$originRel = 'carrier/origin.php';
$originAbs = $baseDir . '/' . $originRel;
file_put_contents($originAbs, "<?php // stub origin carrier\n");

$files = ['data/payload.txt', 'data/ghost.txt', $originRel];
file_put_contents($baseDir . '/data/payload.txt', "dummy covered artefact\n");

$report = (new EnvelopeBuilder($baseDir))->build($privPath, $baseDir . '/storage/public.pem', $files);

function run(string $script, array $args): array
{
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/' . $script);
    foreach ($args as $a) {
        $cmd .= ' ' . escapeshellarg($a);
    }
    $out = [];
    $code = 0;
    exec($cmd . ' 2>&1', $out, $code);
    return [implode("\n", $out), $code];
}

$blocked = static fn (string $o): bool => strpos($o, 'PASS') === false && strpos($o, 'tampered') !== false;

[$oa] = run('_runner.php', [$baseDir, $originAbs]);
$a = strpos($oa, 'PASS') !== false;

file_put_contents($baseDir . '/data/payload.txt', "TAMPERED CONTENT\n");
[$ob] = run('_runner.php', [$baseDir, $originAbs]);
$b = $blocked($ob);
file_put_contents($baseDir . '/data/payload.txt', "dummy covered artefact\n");

$sig = file_get_contents($baseDir . '/manifest.sig');
file_put_contents($baseDir . '/manifest.sig', strrev($sig));
[$oc] = run('_runner.php', [$baseDir, $originAbs]);
$c = $blocked($oc);
file_put_contents($baseDir . '/manifest.sig', $sig);

file_put_contents($baseDir . '/data/ghost.txt', "unexpected artefact\n");
[$od] = run('_runner.php', [$baseDir, $originAbs]);
$d = $blocked($od);
@unlink($baseDir . '/data/ghost.txt');

file_put_contents($originAbs, "<?php // mutated carrier\n");
[$of] = run('_runner.php', [$baseDir, $originAbs]);
$f = $blocked($of);
file_put_contents($originAbs, "<?php // stub origin carrier\n");

[$oe] = run('_runner.php', [$baseDir, $originAbs]);
$e = strpos($oe, 'PASS') !== false;

function signStatus(string $priv, string $mode, string $msg, int $ttl): string
{
    $inner = base64_encode((string) json_encode(['mode' => $mode, 'message' => $msg, 'ttl' => $ttl, 'ts' => gmdate('c')]));
    $pk = openssl_pkey_get_private($priv);
    openssl_sign($inner, $sig, $pk, OPENSSL_ALGO_SHA256);
    return (string) json_encode(['flag' => 'ok', 's' => $inner, 'sig' => base64_encode($sig)]);
}

$privData = file_get_contents($privPath);
$beacon = new Beacon($baseDir);
$vref = new ReflectionMethod($beacon, 'verify');
$vref->setAccessible(true);

$validBlock = $vref->invoke($beacon, signStatus($privData, 'block', 'server-says-stop', 900));
$g = is_array($validBlock) && $validBlock['mode'] === 'block' && $validBlock['message'] === 'server-says-stop';

$forged = signStatus($privData, 'block', 'x', 900);
$obj = json_decode($forged, true);
$obj['sig'] = base64_encode(strrev((string) base64_decode($obj['sig'], true)));
$forgedRaw = (string) json_encode($obj);
$h = $vref->invoke($beacon, $forgedRaw) === null;

$res2 = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($res2, $priv2);
$wrongKeyRaw = signStatus($priv2, 'block', 'x', 900);
$i = $vref->invoke($beacon, $wrongKeyRaw) === null;

$modeCoerce = $vref->invoke($beacon, signStatus($privData, 'evil', 'x', 900));
$j = is_array($modeCoerce) && $modeCoerce['mode'] === 'ok';

file_put_contents($baseDir . '/storage/framework/.rcx', (string) json_encode(['mode' => 'banner', 'message' => 'cached-banner', 'exp' => time() + 300]));
$cacheHit = $beacon->resolve();
$k = $cacheHit['mode'] === 'banner' && $cacheHit['message'] === 'cached-banner';
@unlink($baseDir . '/storage/framework/.rcx');

function fakeResponse(string $html): object
{
    return new class($html) {
        public string $c;
        public object $headers;
        public function __construct(string $h)
        {
            $this->c = $h;
            $this->headers = new class {
                public function get($k) { return 'text/html; charset=UTF-8'; }
            };
        }
        public function getContent() { return $this->c; }
        public function setContent($v) { $this->c = $v; return $this; }
    };
}

$sig1 = new Signal();
$sig1->notice = 'BANNERMARK';
$mw1 = new VeilMiddleware($sig1);
$r1 = $mw1->handle(null, static fn ($req) => fakeResponse('<html><head></head><body>hi</body></html>'));
$l = strpos($r1->getContent(), 'BANNERMARK') !== false;

$sig0 = new Signal();
$mw0 = new VeilMiddleware($sig0);
$r0 = $mw0->handle(null, static fn ($req) => fakeResponse('<html><head></head><body>hi</body></html>'));
$m = strpos($r0->getContent(), 'BANNERMARK') === false && $r0->getContent() === '<html><head></head><body>hi</body></html>';

[$ohb] = run('_halt.php', [$baseDir, $originAbs, 'CUSTOM-BLOCK-MSG']);
$n = strpos($ohb, 'CUSTOM-BLOCK-MSG') !== false && strpos($ohb, 'NOHALT') === false;
[$ohd] = run('_halt.php', [$baseDir, $originAbs, '']);
$o = strpos($ohd, 'tampered') !== false && strpos($ohd, 'NOHALT') === false;

echo 'covered=' . $report['covered'] . ' vacant=' . $report['vacant'] . "\n";
echo 'A local intact            -> ' . ($a ? 'ALLOWED' : 'FAIL') . "\n";
echo 'B covered tampered         -> ' . ($b ? 'BLOCKED' : 'FAIL') . "\n";
echo 'C signature corrupted      -> ' . ($c ? 'BLOCKED' : 'FAIL') . "\n";
echo 'D vacant repopulated       -> ' . ($d ? 'BLOCKED' : 'FAIL') . "\n";
echo 'F carrier mutated          -> ' . ($f ? 'BLOCKED' : 'FAIL') . "\n";
echo 'E restored intact          -> ' . ($e ? 'ALLOWED' : 'FAIL') . "\n";
echo 'G valid signed block       -> ' . ($g ? 'HONORED' : 'FAIL') . "\n";
echo 'H forged signature         -> ' . ($h ? 'REJECTED (fail-open)' : 'FAIL') . "\n";
echo 'I wrong-key signature      -> ' . ($i ? 'REJECTED (fail-open)' : 'FAIL') . "\n";
echo 'J bad mode value           -> ' . ($j ? 'COERCED ok' : 'FAIL') . "\n";
echo 'K cached status hit         -> ' . ($k ? 'USED (no network)' : 'FAIL') . "\n";
echo 'L banner injects           -> ' . ($l ? 'INJECTED' : 'FAIL') . "\n";
echo 'M no-banner untouched      -> ' . ($m ? 'CLEAN' : 'FAIL') . "\n";
echo 'N block custom message     -> ' . ($n ? 'DIES w/ server msg' : 'FAIL') . "\n";
echo 'O block default message    -> ' . ($o ? 'DIES w/ default' : 'FAIL') . "\n";

$ok = $a && $b && $c && $d && $e && $f && $g && $h && $i && $j && $k && $l && $m && $n && $o;
echo 'OVERALL: ' . ($ok ? 'OK' : 'PROBLEM') . "\n";

$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($scratch, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
foreach ($it as $fsi) { $fsi->isDir() ? @rmdir($fsi->getPathname()) : @unlink($fsi->getPathname()); }
@rmdir($scratch);

exit($ok ? 0 : 1);