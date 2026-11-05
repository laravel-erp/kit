<?php

declare(strict_types=1);

namespace LaravelErp\Bridge\Http;

use Closure;
use LaravelErp\Bridge\Runtime\Signal;

final class VeilMiddleware
{
    private Signal $signal;

    public function __construct(Signal $signal)
    {
        $this->signal = $signal;
    }

    public function handle($request, Closure $next)
    {
        $response = $next($request);

        try {
            $notice = $this->signal->notice;
            if ($notice === null || $notice === '') {
                return $response;
            }

            if (! method_exists($response, 'getContent') || ! method_exists($response, 'setContent')) {
                return $response;
            }

            $ctype = $response->headers->get('Content-Type');
            if ($ctype === null || stripos($ctype, 'text/html') === false) {
                return $response;
            }

            $html = $response->getContent();
            if (! is_string($html) || stripos($html, '</body>') === false) {
                return $response;
            }

            $bar = '<div style="position:fixed;top:0;left:0;right:0;z-index:2147483647;'
                . 'background:#b00020;color:#fff;font:14px/1.4 sans-serif;'
                . 'padding:10px 16px;text-align:center;">'
                . htmlspecialchars($notice, ENT_QUOTES, 'UTF-8')
                . '</div>';

            $out = preg_replace('/<body([^>]*)>/i', '<body$1>' . $bar, $html, 1);
            if (is_string($out)) {
                $response->setContent($out);
            }
        } catch (\Throwable $e) {
            return $response;
        }

        return $response;
    }
}