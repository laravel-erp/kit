<?php

declare(strict_types=1);

namespace LaravelErp\Bridge\Runtime;

final class RegionCatalog
{
    private const VACANT = 'absent';

    private const SALT = 'brg/1';

    private string $base;

    private array $anchors = [];

    private array $catalog = [];

    private ?string $tripped = null;

    /** @var null|callable */
    private $reporter = null;

    private static bool $settled = false;

    public function __construct(string $basePath, string $originFile)
    {
        $this->base = rtrim(str_replace('\\', '/', $basePath), '/');

        foreach ([$originFile, __FILE__] as $carrier) {
            $normal = str_replace('\\', '/', $carrier);
            $rel = $this->relativise($normal);
            if ($rel !== $normal) {
                $this->anchors[] = $rel;
            }
        }
    }

    public function setReporter(callable $reporter): void
    {
        $this->reporter = $reporter;
    }

    public function evaluate(): void
    {
        if (self::$settled) {
            return;
        }
        self::$settled = true;

        $intact = $this->primeChannel()
            && $this->reconcileCatalog()
            && $this->confirmPosture();

        if (! $intact) {
            if ($this->reporter !== null) {
                try {
                    ($this->reporter)($this->tripped);
                } catch (\Throwable $e) {
                }
            }
            $this->haltPipeline(null);
        }
    }

    public function halt(?string $override = null): void
    {
        $this->haltPipeline($override);
    }

    private function primeChannel(): bool
    {
        $pub = $this->readBlob($this->base . '/' . $this->loc('a'));
        $env = $this->readBlob($this->base . '/' . $this->loc('b'));
        $sig = $this->readBlob($this->base . '/' . $this->loc('c'));

        if ($pub === null || $env === null || $sig === null) {
            return false;
        }

        $rawSig = base64_decode(trim($sig), true);
        if ($rawSig === false) {
            return false;
        }

        if (openssl_verify($env, $rawSig, $pub, OPENSSL_ALGO_SHA256) !== 1) {
            return false;
        }

        $plain = $this->unseal($env, $pub);
        if ($plain === null) {
            return false;
        }

        $decoded = json_decode($plain, true);
        if (! is_array($decoded) || ! isset($decoded['files']) || ! is_array($decoded['files'])) {
            return false;
        }

        $this->catalog = $decoded['files'];

        return $this->catalog !== [];
    }

    private function reconcileCatalog(): bool
    {
        foreach ($this->catalog as $relative => $expected) {
            $full = $this->base . '/' . ltrim((string) $relative, '/');

            if ($expected === self::VACANT) {
                if (is_file($full)) {
                    $this->tripped = (string) $relative;

                    return false;
                }
                continue;
            }

            if (! is_file($full)) {
                // A module may be omitted on an install that never licensed it.
                // If the file is later dropped in, the hash check below runs.
                if ($this->isModuleCarrier((string) $relative)) {
                    continue;
                }
                $this->tripped = (string) $relative;

                return false;
            }

            $actual = hash_file('sha256', $full);
            if ($actual === false || ! hash_equals((string) $expected, $actual)) {
                $this->tripped = (string) $relative;

                return false;
            }
        }

        return true;
    }

    private function confirmPosture(): bool
    {
        foreach ($this->anchors as $rel) {
            if (! array_key_exists($rel, $this->catalog)) {
                $this->tripped = $rel;

                return false;
            }
        }

        return true;
    }

    private function unseal(string $env, string $pub): ?string
    {
        $raw = base64_decode(trim($env), true);
        if ($raw === false || strlen($raw) <= 16) {
            return null;
        }

        $iv = substr($raw, 0, 16);
        $ct = substr($raw, 16);
        $key = hash_hkdf('sha256', hash('sha256', $pub, true), 32, self::SALT);

        $plain = openssl_decrypt($ct, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

        return $plain === false ? null : $plain;
    }

    private function isModuleCarrier(string $rel): bool
    {
        $root = (string) base64_decode('TW9kdWxlcw==', true);
        $suffix = (string) base64_decode('SHR0cC9Db250cm9sbGVycy9JbnN0YWxsQ29udHJvbGxlci5waHA=', true);

        return str_starts_with($rel, $root . '/') && str_ends_with($rel, '/' . $suffix);
    }

    private function relativise(string $abs): string
    {
        $abs = str_replace('\\', '/', $abs);
        $prefix = $this->base . '/';
        if (strncmp($abs, $prefix, strlen($prefix)) === 0) {
            return substr($abs, strlen($prefix));
        }

        return $abs;
    }

    private function loc(string $k): string
    {
        static $t = null;
        if ($t === null) {
            $t = [
                'a' => 'c3RvcmFnZS9wdWJsaWMucGVt',
                'b' => 'c3RvcmFnZS9mcmFtZXdvcmsvLnJkeA==',
                'c' => 'c3RvcmFnZS9mcmFtZXdvcmsvLnJkcw==',
            ];
        }

        return (string) base64_decode($t[$k] ?? '', true);
    }

    private function readBlob(string $path): ?string
    {
        if (! is_file($path)) {
            return null;
        }

        $data = @file_get_contents($path);

        return $data === false ? null : $data;
    }

    private function haltPipeline(?string $override): void
    {
        if (is_string($override) && $override !== '') {
            die($override);
        }

        $m = base64_decode('VGhlIGFwcGxpY2F0aW9uIGhhcyBiZWVuIHRhbXBlcmVkIHdpdGggYW5kIGNhbm5vdCBiZSBydW4u', true);
        die($m === false ? '' : $m);
    }
}