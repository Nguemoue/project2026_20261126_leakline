<?php

declare(strict_types=1);

/**
 * Behavioral checks for leakline. Secrets are assembled at runtime and
 * written under the system temp dir so this file stays safe to commit.
 */

$failures = 0;

function note(bool $ok, string $message): void
{
    global $failures;
    if ($ok) {
        fwrite(STDOUT, "ok   {$message}\n");
        return;
    }
    $failures++;
    fwrite(STDERR, "FAIL {$message}\n");
}

function body(string $unit, int $length): string
{
    $out = '';
    while (strlen($out) < $length) {
        $out .= $unit;
    }
    return substr($out, 0, $length);
}

function aws_key(): string
{
    return ('AK' . 'IA') . body('ABC2', 16);
}

function github_token(): string
{
    return ('gh' . 'p_') . body('Ab9', 36);
}

function stripe_live(): string
{
    return ('sk' . '_live_') . body('aB3c', 24);
}

function stripe_test(): string
{
    return ('sk' . '_test_') . body('dE4f', 24);
}

function private_header(): string
{
    return '-----' . 'BEGIN ' . 'PRIVATE' . ' KEY' . '-----';
}

function db_password(): string
{
    return 'pQ7!' . 'mN2$kL9@xR4';
}

function generic_secret(): string
{
    return 'aB3$' . 'k9Qm2Lx7!pZ4';
}

function database_url(): string
{
    return 'mysql://app:' . db_password() . '@db.internal:3306/app';
}

/**
 * @param list<string> $args
 * @return array{0:int,1:string,2:string}
 */
function run_leakline(array $args): array
{
    $script = dirname(__DIR__) . '/leakline.php';
    $command = array_merge([PHP_BINARY, $script], $args);
    $proc = proc_open($command, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes);
    if (!is_resource($proc)) {
        return [99, '', 'proc_open failed'];
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc), is_string($stdout) ? $stdout : '', is_string($stderr) ? $stderr : ''];
}

function write_tree(string $root, array $files): void
{
    foreach ($files as $rel => $contents) {
        $path = $root . '/' . $rel;
        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0777, true) && !is_dir($dir)) {
            throw new RuntimeException('mkdir failed: ' . $dir);
        }
        if (file_put_contents($path, $contents) === false) {
            throw new RuntimeException('write failed: ' . $path);
        }
    }
}

$root = dirname(__DIR__);
[$code, $out, $err] = run_leakline(['--no-color', $root]);
note($code === 0, 'repository itself is clean');
note(str_contains($out, 'clean'), 'clean repository says clean');
note($err === '', 'clean repository has empty stderr: ' . $err);

[$code, $out] = run_leakline(['--help']);
note($code === 0 && str_contains($out, 'leakline'), 'help exits 0');

[$code] = run_leakline(['--version']);
note($code === 0, 'version exits 0');

[$code, $out, $err] = run_leakline(['--no-color', $root . '/this-path-does-not-exist']);
note($code === 2, 'missing path exits 2');
note(str_contains($err, 'path not found'), 'missing path explains itself');

$dirty = sys_get_temp_dir() . '/leakline-dirty-' . bin2hex(random_bytes(4));
mkdir($dirty, 0777, true);

$aws = aws_key();
$ghIgnored = github_token();
$ghSameLine = github_token() . 'Z';
$live = stripe_live();
$testKey = stripe_test();
$pass = db_password();
$generic = generic_secret();
$url = database_url();
$header = private_header();

write_tree($dirty, [
    'app/config.php' => "<?php\n\$region = 'eu-west-1';\n\$key = '{$aws}';\n\$password = 'changeme';\n// leakline:ignore\n\$gh = '{$ghIgnored}';\n\$also = '{$ghSameLine}'; // leakline:ignore\n",
    'app/login.php' => "<?php\n\$api_key = '{$generic}';\n",
    '.env' => "APP_NAME=Acme\nSTRIPE_SECRET={$live}\nDB_PASSWORD={$pass}\n",
    '.env.example' => "APP_KEY=\nSTRIPE_SECRET={$testKey}\nAPI_KEY=your-api-key\n",
    '.env.testing' => "DB_PASSWORD=secret\nAPP_ENV=testing\n",
    '.env.local' => '',
    'vendor/evil.php' => "<?php\n\$key = '{$aws}';\n",
    'docs/db.md' => "Connect with {$url} in local only.\n",
    'keys/dev.pem' => $header . "\nMIIB-not-a-real-key\n-----END-----\n",
    'readme.txt' => "Placeholders only: your-api-key, changeme, null.\n",
]);

[$code, $out, $err] = run_leakline(['--json', '--no-color', $dirty]);
note($code === 1, 'dirty tree exits 1');
$report = json_decode($out, true);
note(is_array($report), 'json report parses');

$rules = [];
$files = [];
if (is_array($report)) {
    foreach ($report['findings'] as $finding) {
        $rules[] = $finding['rule'];
        $files[] = $finding['file'];
    }
}
$counts = array_count_values($rules);
$expected = [
    'aws_access_key' => 1,
    'private_key' => 1,
    'stripe_live_key' => 1,
    'stripe_test_key' => 1,
    'dotenv_committed' => 2,
    'dotenv_secret' => 1,
    'database_url' => 1,
    'generic_secret' => 1,
];
ksort($expected);
$actual = $counts;
ksort($actual);
note($actual === $expected, 'finding rules match expected set: ' . json_encode($actual));

$blob = $out . $err;
foreach (['aws' => $aws, 'live' => $live, 'test' => $testKey, 'gh' => $ghIgnored, 'pass' => $pass, 'generic' => $generic, 'header' => $header] as $name => $secret) {
    note(!str_contains($blob, $secret), "report does not contain raw {$name}");
}
note(str_contains($out, '•'), 'report masks with a bullet');
$leakedVendor = false;
foreach ($files as $file) {
    if (str_contains($file, '/vendor/')) {
        $leakedVendor = true;
    }
}
note(!$leakedVendor, 'vendor directory is ignored');
note(!str_contains($blob, $ghSameLine), 'same-line ignore hides the token');

$clean = sys_get_temp_dir() . '/leakline-clean-' . bin2hex(random_bytes(4));
mkdir($clean, 0777, true);
write_tree($clean, [
    'app/ok.php' => "<?php\n\$password = 'changeme';\n\$api_key = 'your-api-key';\n\$token = 'xxxxxxxxxxxxxxxx';\n\$path = '/var/app/config.php';\n",
    '.env.example' => "APP_KEY=\nDB_PASSWORD=\nAPI_KEY=your-api-key\nAWS_SECRET_ACCESS_KEY=\n",
    '.env.testing' => "DB_PASSWORD=secret\n",
    'docs/note.md' => "Use mysql://app:password@localhost/db as the shape, never a real one.\n",
]);
[$code, $out] = run_leakline(['--no-color', $clean]);
note($code === 0, 'placeholders and .env.example are clean');
note(str_contains($out, 'clean'), 'placeholder tree says clean');

$only = sys_get_temp_dir() . '/leakline-disable-' . bin2hex(random_bytes(4));
mkdir($only, 0777, true);
write_tree($only, [
    'config.php' => "<?php\n\$key = '{$aws}';\n",
]);
[$code] = run_leakline(['--no-color', '--disable=aws_access_key', $only]);
note($code === 0, '--disable can turn a rule off');

$ignored = sys_get_temp_dir() . '/leakline-ignore-' . bin2hex(random_bytes(4));
mkdir($ignored, 0777, true);
write_tree($ignored, [
    '.leaklineignore' => "hidden/\nrule:stripe_test_key\n",
    'hidden/key.php' => "<?php\n\$key = '{$aws}';\n",
    'billing.php' => "<?php\n\$k = '{$testKey}';\n",
    'app.php' => "<?php\n\$api_key = '{$generic}';\n",
]);
[$code, $out] = run_leakline(['--json', '--no-color', $ignored]);
$report = json_decode($out, true);
$rules = [];
if (is_array($report)) {
    foreach ($report['findings'] as $finding) {
        $rules[] = $finding['rule'];
    }
}
note($code === 1 && $rules === ['generic_secret'], '.leaklineignore skips a path and a rule, got ' . json_encode($rules));

if ($failures > 0) {
    fwrite(STDERR, "\n{$failures} failed.\n");
    exit(1);
}

fwrite(STDOUT, "\nall checks passed.\n");
