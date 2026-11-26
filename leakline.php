#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * leakline — zero-dependency secret scanner.
 *
 * Reads local files only, prints masked snippets, exits 1 when a secret
 * (or a real .env file) is found. Nothing is uploaded.
 */

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === realpath(__FILE__)) {
    exit((new Leakline())->run(array_slice($argv, 1)));
}

final class Leakline
{
    private const VERSION = '1.0.0';

    /** @var list<string> */
    private const SKIP_DIRS = [
        'vendor',
        'node_modules',
        '.git',
        '.svn',
        '.hg',
        'bower_components',
        'coverage',
        '.phpunit.cache',
        '.idea',
        '.next',
        '.nuxt',
    ];

    /** @var list<string> */
    private const SKIP_PREFIXES = [
        'storage/framework/',
        'storage/logs/',
        'bootstrap/cache/',
        'public/build/',
    ];

    /** @var list<string> */
    private const TEXT_EXTENSIONS = [
        'php', 'phtml', 'inc', 'env', 'json', 'js', 'mjs', 'cjs', 'ts', 'tsx',
        'jsx', 'vue', 'yml', 'yaml', 'xml', 'ini', 'conf', 'toml', 'twig',
        'sql', 'sh', 'bash', 'zsh', 'md', 'txt', 'neon', 'dist', 'properties',
        'cfg', 'py', 'rb', 'go', 'java', 'kt', 'swift', 'cs', 'ex', 'exs',
        'envrc', 'htaccess', 'pem', 'key', 'crt', 'tf', 'hcl', 'gradle',
        'dockerfile', 'xml', 'yml',
    ];

    private bool $asJson = false;
    private bool $quiet = false;
    private bool $color = false;
    private int $maxBytes = 1048576;

    /** @var list<string> */
    private array $extraIgnores = [];

    /** @var list<string> */
    private array $disabledRules = [];

    /**
     * @param list<string> $args
     */
    public function run(array $args): int
    {
        $paths = [];
        foreach ($args as $arg) {
            if ($arg === '--help' || $arg === '-h') {
                fwrite(STDOUT, $this->help());
                return 0;
            }
            if ($arg === '--version' || $arg === '-V') {
                fwrite(STDOUT, self::VERSION . "\n");
                return 0;
            }
            if ($arg === '--json') {
                $this->asJson = true;
                continue;
            }
            if ($arg === '--quiet' || $arg === '-q') {
                $this->quiet = true;
                continue;
            }
            if ($arg === '--no-color') {
                $this->color = false;
                continue;
            }
            if ($arg === '--color') {
                $this->color = true;
                continue;
            }
            if (str_starts_with($arg, '--max-size=')) {
                $n = (int) substr($arg, strlen('--max-size='));
                if ($n < 1) {
                    return $this->fail('--max-size must be a positive number of bytes');
                }
                $this->maxBytes = $n;
                continue;
            }
            if (str_starts_with($arg, '--ignore=')) {
                foreach (explode(',', substr($arg, strlen('--ignore='))) as $piece) {
                    $piece = trim($piece);
                    if ($piece !== '') {
                        $this->extraIgnores[] = $piece;
                    }
                }
                continue;
            }
            if (str_starts_with($arg, '--disable=')) {
                foreach (explode(',', substr($arg, strlen('--disable='))) as $piece) {
                    $piece = trim($piece);
                    if ($piece !== '') {
                        $this->disabledRules[] = $piece;
                    }
                }
                continue;
            }
            if (str_starts_with($arg, '-')) {
                fwrite(STDERR, "leakline: unknown option {$arg}\n\n");
                fwrite(STDOUT, $this->help());
                return 2;
            }
            $paths[] = $arg;
        }

        if ($this->asJson) {
            $this->color = false;
        } elseif (!$this->color && stream_isatty(STDOUT)) {
            $this->color = true;
        }

        if ($paths === []) {
            $paths = ['.'];
        }

        foreach ($paths as $path) {
            if (!file_exists($path)) {
                return $this->fail('path not found: ' . $path);
            }
        }

        $findings = [];
        foreach ($paths as $path) {
            foreach ($this->scanPath($path) as $finding) {
                $findings[] = $finding;
            }
        }

        usort($findings, static function (array $a, array $b): int {
            $rank = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
            $bySev = ($rank[$a['severity']] ?? 9) <=> ($rank[$b['severity']] ?? 9);
            if ($bySev !== 0) {
                return $bySev;
            }
            return [$a['file'], $a['line'], $a['rule']] <=> [$b['file'], $b['line'], $b['rule']];
        });

        $this->report($findings, $paths);

        return $findings === [] ? 0 : 1;
    }

    private function help(): string
    {
        return <<<TXT
leakline 1.0.0 — stop secrets before they reach git.

Usage:
  php leakline.php [options] [path...]

Options:
  --json              JSON report on stdout (masked snippets only)
  --quiet, -q         Findings and summary only
  --no-color          Plain text
  --color             Force ANSI colors
  --max-size=BYTES    Skip files larger than this (default 1048576)
  --ignore=A,B        Extra directory names or path prefixes to skip
  --disable=RULE      Comma-separated rule ids to turn off
  -h, --help          Show this help
  -V, --version       Print version

Exit codes:
  0  nothing found
  1  at least one finding
  2  bad usage or unreadable path

Ignore one line with a comment containing leakline:ignore.
A line that is only "// leakline:ignore" or "# leakline:ignore" ignores
the next line. A .leaklineignore file at the scan root skips paths
(one glob or prefix per line) and can disable rules with "rule:name".

The report never prints a full secret. leakline does not use the network.

TXT;
    }

    /**
     * @param list<array{file:string,line:int,rule:string,severity:string,title:string,mask:string}> $findings
     * @param list<string> $paths
     */
    private function report(array $findings, array $paths): void
    {
        if ($this->asJson) {
            fwrite(STDOUT, json_encode([
                'tool' => 'leakline',
                'version' => self::VERSION,
                'ok' => $findings === [],
                'scanned' => $paths,
                'counts' => $this->counts($findings),
                'findings' => $findings,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
            return;
        }

        if (!$this->quiet) {
            fwrite(STDOUT, $this->paint('leakline', '36') . ' ' . self::VERSION . "\n");
        }

        foreach ($findings as $finding) {
            $color = match ($finding['severity']) {
                'critical' => '31',
                'high' => '91',
                'medium' => '33',
                default => '37',
            };
            fwrite(STDOUT, $finding['file'] . ':' . $finding['line']
                . '  ' . $this->paint('[' . $finding['severity'] . ']', $color)
                . '  ' . $finding['rule'] . "\n");
            fwrite(STDOUT, '  ' . $finding['title'] . "\n");
            if ($finding['mask'] !== '') {
                fwrite(STDOUT, '  ' . $finding['mask'] . "\n");
            }
        }

        if ($findings === []) {
            fwrite(STDOUT, $this->paint('clean', '32') . " — no secrets found.\n");
            return;
        }

        $parts = [];
        foreach ($this->counts($findings) as $severity => $count) {
            if ($count > 0) {
                $parts[] = $count . ' ' . $severity;
            }
        }
        fwrite(STDOUT, "\n" . $this->paint(implode(', ', $parts), '31') . " — do not push this.\n");
    }

    /**
     * @param list<array{severity:string}> $findings
     * @return array{critical:int,high:int,medium:int,low:int}
     */
    private function counts(array $findings): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($findings as $finding) {
            if (isset($counts[$finding['severity']])) {
                $counts[$finding['severity']]++;
            }
        }
        return $counts;
    }

    private function paint(string $text, string $code): string
    {
        if (!$this->color) {
            return $text;
        }
        return "\033[{$code}m{$text}\033[0m";
    }

    private function fail(string $message): int
    {
        if ($this->asJson) {
            fwrite(STDOUT, json_encode([
                'tool' => 'leakline',
                'version' => self::VERSION,
                'ok' => false,
                'error' => $message,
            ], JSON_UNESCAPED_SLASHES) . "\n");
            return 2;
        }
        fwrite(STDERR, "leakline: {$message}\n");
        return 2;
    }

    /**
     * @return list<array{file:string,line:int,rule:string,severity:string,title:string,mask:string}>
     */
    private function scanPath(string $path): array
    {
        $real = realpath($path);
        if ($real === false) {
            return [];
        }

        $displayRoot = rtrim(str_replace('\\', '/', $path), '/');
        $ignoreRoot = is_dir($real) ? $real : dirname($real);
        $ignores = $this->loadIgnoreFile($ignoreRoot);
        $disabled = array_values(array_unique(array_merge($this->disabledRules, $ignores['rules'])));

        if (is_file($real)) {
            return $this->scanFile($real, $displayRoot, $disabled);
        }

        $findings = [];
        $filter = new RecursiveCallbackFilterIterator(
            new RecursiveDirectoryIterator($real, FilesystemIterator::SKIP_DOTS),
            function (SplFileInfo $info) use ($real, $ignores): bool {
                $rel = $this->relative($real, $info->getPathname());
                return !$this->shouldSkip($rel, $ignores['paths']);
            }
        );

        $iterator = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::LEAVES_ONLY);
        /** @var SplFileInfo $info */
        foreach ($iterator as $info) {
            if (!$info->isFile()) {
                continue;
            }
            $full = $info->getPathname();
            $rel = $this->relative($real, $full);
            if ($rel === '.leaklineignore' || !$this->shouldScanFile($rel)) {
                continue;
            }
            $label = ($displayRoot === '' || $displayRoot === '.') ? $rel : $displayRoot . '/' . $rel;
            foreach ($this->scanFile($full, $label, $disabled) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * @param list<string> $disabled
     * @return list<array{file:string,line:int,rule:string,severity:string,title:string,mask:string}>
     */
    private function scanFile(string $full, string $label, array $disabled): array
    {
        if (!$this->shouldScanFile($label)) {
            return [];
        }

        $handle = @fopen($full, 'rb');
        if ($handle === false) {
            return [];
        }
        $contents = stream_get_contents($handle, $this->maxBytes + 1);
        fclose($handle);
        if (!is_string($contents)) {
            return [];
        }

        $base = basename(str_replace('\\', '/', $label));
        $findings = [];
        if ($this->isRiskyDotenv($base) && !in_array('dotenv_committed', $disabled, true)) {
            $findings[] = $this->finding($label, 1, 'dotenv_committed', 'high', 'Real dotenv file (keep it out of git)', '');
        }

        if ($contents === '' || strlen($contents) > $this->maxBytes || str_contains($contents, "\0")) {
            return $findings;
        }

        $family = $base === '.env' || str_starts_with($base, '.env.');
        $lines = preg_split("/\n/", $contents) ?: [];
        $skipNext = false;
        foreach ($lines as $index => $line) {
            $trim = rtrim($line, "\r");
            $bareIgnore = preg_match('/^(\/\/|#)\s*leakline:ignore\s*$/', trim($trim)) === 1;
            if ($skipNext || str_contains($trim, 'leakline:ignore')) {
                $skipNext = $bareIgnore;
                continue;
            }
            $skipNext = false;
            foreach ($this->matchLine($trim, $family, strlen($trim) > 500, $disabled) as $match) {
                $findings[] = $this->finding(
                    $label,
                    $index + 1,
                    $match['rule'],
                    $match['severity'],
                    $match['title'],
                    $this->maskSecret($match['secret'], $match['rule'])
                );
            }
        }

        return $findings;
    }

    /**
     * @param list<string> $disabled
     * @return list<array{rule:string,severity:string,title:string,secret:string}>
     */
    private function matchLine(string $line, bool $dotenvFamily, bool $longLine, array $disabled): array
    {
        $found = [];
        $specific = false;
        foreach ($this->rules() as $rule) {
            if ($rule['id'] === 'generic_secret' || $rule['id'] === 'dotenv_secret') {
                continue;
            }
            if (in_array($rule['id'], $disabled, true)) {
                continue;
            }
            foreach ($rule['patterns'] as $pattern) {
                if (!preg_match($pattern, $line, $matches)) {
                    continue;
                }
                $secret = $matches[1] ?? $matches[0];
                if (!is_string($secret) || $secret === '') {
                    continue;
                }
                if ($rule['id'] === 'database_url') {
                    $password = $matches[2] ?? '';
                    if (!is_string($password) || $this->isPlaceholder($password) || strlen($password) < 4) {
                        continue;
                    }
                } elseif ($this->isPlaceholder($secret)) {
                    continue;
                }
                $found[] = [
                    'rule' => $rule['id'],
                    'severity' => $rule['severity'],
                    'title' => $rule['title'],
                    'secret' => $secret,
                ];
                $specific = true;
                break;
            }
        }

        if ($specific || $longLine) {
            return $found;
        }

        if ($dotenvFamily && !in_array('dotenv_secret', $disabled, true)) {
            if (preg_match('/(?:^|[^A-Za-z0-9_])((?:[A-Z0-9_]*_)?(?:PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY|APP_KEY))\s*=\s*([\'"]?)([^\s#\'"]{12,})\2/i', $line, $matches)) {
                $secret = $matches[3];
                if ($this->looksSecret($secret)) {
                    $found[] = [
                        'rule' => 'dotenv_secret',
                        'severity' => 'high',
                        'title' => 'Secret assignment in a dotenv file (' . $matches[1] . ')',
                        'secret' => $secret,
                    ];
                }
            }
            return $found;
        }

        if (!in_array('generic_secret', $disabled, true)) {
            $pattern = '/\b(api[_-]?key|apikey|api[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|secret[_-]?key|private[_-]?token|password|passwd)\b\s*[=:]\s*([\'"])([^\'"\r\n]{12,})\2/i';
            if (preg_match($pattern, $line, $matches) && $this->looksSecret($matches[3])) {
                $found[] = [
                    'rule' => 'generic_secret',
                    'severity' => 'medium',
                    'title' => 'High-entropy value assigned to ' . $matches[1],
                    'secret' => $matches[3],
                ];
            }
        }

        return $found;
    }

    /**
     * @return list<array{id:string,severity:string,title:string,patterns:list<string>}>
     */
    private function rules(): array
    {
        $begin = '-----' . 'BEGIN ';
        $end = 'PRIVATE' . ' KEY-----';
        $privateKey = '/(' . preg_quote($begin, '/') . '(?:RSA |OPENSSH |EC |DSA |PGP )?' . preg_quote($end, '/') . ')/';

        return [
            [
                'id' => 'private_key',
                'severity' => 'critical',
                'title' => 'Private key block',
                'patterns' => [$privateKey],
            ],
            [
                'id' => 'aws_access_key',
                'severity' => 'critical',
                'title' => 'AWS access key id',
                'patterns' => ['/\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/'],
            ],
            [
                'id' => 'aws_secret_key',
                'severity' => 'critical',
                'title' => 'AWS secret access key',
                'patterns' => ['/(?:aws[_-]?secret(?:[_-]?access[_-]?key)?|AWS_SECRET_ACCESS_KEY)[\'"\s:=]{1,16}([A-Za-z0-9\/+]{40})(?:[\'"\s]|$)/i'],
            ],
            [
                'id' => 'stripe_live_key',
                'severity' => 'critical',
                'title' => 'Stripe live secret key',
                'patterns' => ['/\b((?:sk|rk)_live_[0-9a-zA-Z]{16,})\b/'],
            ],
            [
                'id' => 'github_token',
                'severity' => 'critical',
                'title' => 'GitHub token',
                'patterns' => [
                    '/\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/',
                    '/\b(github_pat_[A-Za-z0-9_]{22,255})\b/',
                ],
            ],
            [
                'id' => 'slack_token',
                'severity' => 'high',
                'title' => 'Slack token',
                'patterns' => ['/\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/'],
            ],
            [
                'id' => 'slack_webhook',
                'severity' => 'high',
                'title' => 'Slack incoming webhook',
                'patterns' => ['#(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{10,})#'],
            ],
            [
                'id' => 'google_api_key',
                'severity' => 'high',
                'title' => 'Google API key',
                'patterns' => ['/\b(AIza[0-9A-Za-z_\-]{35})\b/'],
            ],
            [
                'id' => 'ai_provider_key',
                'severity' => 'high',
                'title' => 'AI provider API key',
                'patterns' => ['/\b(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,})\b/'],
            ],
            [
                'id' => 'sendgrid_key',
                'severity' => 'high',
                'title' => 'SendGrid API key',
                'patterns' => ['/\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b/'],
            ],
            [
                'id' => 'shopify_token',
                'severity' => 'high',
                'title' => 'Shopify access token',
                'patterns' => ['/\b(shp(?:at|ss|ca|pa)_[a-fA-F0-9]{32})\b/'],
            ],
            [
                'id' => 'npm_token',
                'severity' => 'high',
                'title' => 'npm access token',
                'patterns' => ['/\b(npm_[A-Za-z0-9]{36})\b/'],
            ],
            [
                'id' => 'database_url',
                'severity' => 'high',
                'title' => 'Database URL with a password',
                'patterns' => ['/\b((?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/(?:[^:\/\s\'"]+):([^@\/\s\'"]+)@[^\s\'"]+)/i'],
            ],
            [
                'id' => 'stripe_test_key',
                'severity' => 'medium',
                'title' => 'Stripe test secret key (still do not commit it)',
                'patterns' => ['/\b((?:sk|rk)_test_[0-9a-zA-Z]{16,})\b/'],
            ],
        ];
    }

    private function looksSecret(string $value): bool
    {
        if ($this->isPlaceholder($value)) {
            return false;
        }
        $length = strlen($value);
        if ($length < 12 || $length > 200) {
            return false;
        }
        if (preg_match('/\s/', $value)) {
            return false;
        }
        if (preg_match('#^(https?://|/)#', $value)) {
            return false;
        }
        if (preg_match('/\.(?:php|js|ts|env|json|ya?ml|md|txt)$/i', $value)) {
            return false;
        }
        $hasUpper = preg_match('/[A-Z]/', $value) === 1;
        $hasSymbol = preg_match('/[^A-Za-z0-9]/', $value) === 1;
        $hasDigit = preg_match('/[0-9]/', $value) === 1;
        $hasLower = preg_match('/[a-z]/', $value) === 1;
        if (!$hasUpper && !$hasSymbol) {
            return false;
        }
        if (!$hasDigit && !$hasLower) {
            return false;
        }
        return $this->entropy($value) >= 3.2;
    }

    private function isPlaceholder(string $value): bool
    {
        $value = trim($value);
        if ($value === '') {
            return true;
        }
        $lower = strtolower($value);
        $exact = [
            'null', 'true', 'false', 'none', 'nil', 'undefined', 'changeme',
            'change_me', 'change-me', 'secret', 'password', 'token', 'example',
            'placeholder', 'dummy', 'fake', 'test', 'testing', 'todo', 'fixme',
            'xxx', 'xxxx', 'redacted', 'n/a', 'na', 'password123', 'secret123',
            'admin', 'root', 'guest', 'pass', 'passw0rd', 'base64:',
        ];
        if (in_array($lower, $exact, true)) {
            return true;
        }
        if (preg_match('/^(your|my|some|example|sample|dummy|fake|test|todo|change|insert|add|put|replace)[-_ ]/i', $value)) {
            return true;
        }
        if (preg_match('/(example|placeholder|redacted|changeme|your[-_]?(api[-_]?)?(key|token|secret))/i', $value)) {
            return true;
        }
        if (preg_match('/^[\*xX\.#_\-]+$/', $value)) {
            return true;
        }
        if (preg_match('/^<.*>$/', $value) || str_contains($value, '${') || str_contains($value, '{{')) {
            return true;
        }
        if (str_starts_with($value, '$') || preg_match('/^(?:env\(|getenv\(|config\(|process\.env)/i', $value)) {
            return true;
        }
        if (preg_match('/^(.)\1{7,}$/', $value)) {
            return true;
        }
        return false;
    }

    private function entropy(string $value): float
    {
        $length = strlen($value);
        if ($length === 0) {
            return 0.0;
        }
        $freq = count_chars($value, 1);
        $entropy = 0.0;
        foreach ($freq as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    private function maskSecret(string $secret, string $rule): string
    {
        if ($rule === 'private_key') {
            return '[private key block]';
        }
        if ($rule === 'database_url' && preg_match('#^([a-z0-9+]+://)([^:/]+):([^@]+)@(.+)$#i', $secret, $matches)) {
            return $matches[1] . $matches[2] . ':' . $this->mask($matches[3]) . '@' . $matches[4];
        }
        return $this->mask($secret);
    }

    private function mask(string $secret): string
    {
        $length = strlen($secret);
        if ($length <= 8) {
            return str_repeat('•', $length);
        }
        $hidden = min(12, $length - 7);
        return substr($secret, 0, 4) . str_repeat('•', $hidden) . substr($secret, -3);
    }

    /**
     * @return array{file:string,line:int,rule:string,severity:string,title:string,mask:string}
     */
    private function finding(string $file, int $line, string $rule, string $severity, string $title, string $mask): array
    {
        return [
            'file' => $file,
            'line' => $line,
            'rule' => $rule,
            'severity' => $severity,
            'title' => $title,
            'mask' => $mask,
        ];
    }

    private function isRiskyDotenv(string $base): bool
    {
        if ($base === '.env') {
            return true;
        }
        if (!str_starts_with($base, '.env.')) {
            return false;
        }
        if (preg_match('/\.(example|sample|template|dist|testing|ci)$/', $base)) {
            return false;
        }
        $suffix = substr($base, strlen('.env.'));
        foreach (['local', 'production', 'prod', 'staging', 'stage', 'development', 'dev', 'backup', 'bak', 'live'] as $word) {
            if (preg_match('/(^|[._-])' . $word . '($|[._-])/', $suffix)) {
                return true;
            }
        }
        return false;
    }

    private function shouldScanFile(string $path): bool
    {
        $base = basename(str_replace('\\', '/', $path));
        if ($base === '.leaklineignore') {
            return false;
        }
        if (preg_match('/\.(?:min\.js|min\.css|map|lock|png|jpe?g|gif|webp|ico|woff2?|ttf|eot|zip|gz|phar)$/i', $base)) {
            return false;
        }
        $always = [
            'dockerfile', '.npmrc', '.pypirc', '.envrc', 'wp-config.php',
            'credentials', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
        ];
        if (in_array(strtolower($base), $always, true)) {
            return true;
        }
        if ($base === '.env' || str_starts_with($base, '.env.')) {
            return true;
        }
        $ext = strtolower(pathinfo($base, PATHINFO_EXTENSION));
        return in_array($ext, self::TEXT_EXTENSIONS, true);
    }

    /**
     * @param list<string> $userPaths
     */
    private function shouldSkip(string $rel, array $userPaths): bool
    {
        $rel = trim(str_replace('\\', '/', $rel), '/');
        if ($rel === '' || $rel === '.leaklineignore') {
            return $rel === '.leaklineignore';
        }
        $segments = explode('/', $rel);
        foreach ($segments as $segment) {
            if (in_array($segment, self::SKIP_DIRS, true)) {
                return true;
            }
        }
        foreach (self::SKIP_PREFIXES as $prefix) {
            $bare = rtrim($prefix, '/');
            if ($rel === $bare || str_starts_with($rel, $prefix) || str_starts_with($rel, $bare . '/')) {
                return true;
            }
        }
        foreach (array_merge($userPaths, $this->extraIgnores) as $pattern) {
            if ($this->matchUserPattern($rel, $pattern)) {
                return true;
            }
        }
        return false;
    }

    private function matchUserPattern(string $rel, string $pattern): bool
    {
        $pattern = trim(str_replace('\\', '/', $pattern), '/');
        if ($pattern === '') {
            return false;
        }
        if (strpbrk($pattern, '*?') !== false) {
            return fnmatch($pattern, $rel) || fnmatch($pattern, basename($rel));
        }
        if ($rel === $pattern || str_starts_with($rel, $pattern . '/')) {
            return true;
        }
        return in_array($pattern, explode('/', $rel), true);
    }

    /**
     * @return array{paths:list<string>,rules:list<string>}
     */
    private function loadIgnoreFile(string $root): array
    {
        $paths = [];
        $rules = [];
        $file = rtrim($root, '/') . '/.leaklineignore';
        if (!is_file($file)) {
            return ['paths' => $paths, 'rules' => $rules];
        }
        $lines = file($file, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return ['paths' => $paths, 'rules' => $rules];
        }
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            if (str_starts_with($line, 'rule:')) {
                $rule = trim(substr($line, strlen('rule:')));
                if ($rule !== '') {
                    $rules[] = $rule;
                }
                continue;
            }
            $paths[] = $line;
        }
        return ['paths' => $paths, 'rules' => $rules];
    }

    private function relative(string $root, string $full): string
    {
        $root = rtrim(str_replace('\\', '/', $root), '/');
        $full = str_replace('\\', '/', $full);
        if ($full === $root) {
            return '';
        }
        if (str_starts_with($full, $root . '/')) {
            return substr($full, strlen($root) + 1);
        }
        return ltrim($full, '/');
    }
}
