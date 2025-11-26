<?php
if (!defined('ABSPATH')) exit;

class FW_Firewall {

    private static $inst;

    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    private function __construct() {
        add_action('wp_loaded', array('FW_Firewall', 'basic_firewall'), 1);
        add_filter('authenticate', array('FW_Firewall', 'limit_login_attempts'), 10, 3);
    }

    public static function basic_firewall() {

        $opts = get_option(FortressWP::OPTION_KEY, []);
        $ip   = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // External blocklist IPs
        $blocklist = FW_Signature_Manager::get_blocklist();

        // Manual blocklist IPs
        $manual_ips = isset($opts['manual_block_ips'])
            ? preg_split('/\r?\n/', $opts['manual_block_ips'])
            : [];
        $manual_ips = array_filter(array_map('trim', $manual_ips));

        $all_block_ips = array_unique(array_merge($blocklist, $manual_ips));

        if ($ip && in_array($ip, $all_block_ips, true)) {
            FW_Audit::log('firewall', 'Blocked IP', ['ip' => $ip], 'critical');
            status_header(403);
            wp_die('Forbidden — Your IP has been blocked by FortressWP.');
        }

        // Block suspicious user agents
        $ua  = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $uas = isset($opts['blocked_user_agents'])
            ? preg_split('/\r?\n/', $opts['blocked_user_agents'])
            : [];

        foreach ($uas as $pattern) {
            $pattern = trim($pattern);
            if (!$pattern) continue;

            if (stripos($ua, $pattern) !== false) {
                FW_Audit::log('firewall', 'Blocked User Agent', ['ua' => $ua], 'warning');
                status_header(403);
                wp_die('Forbidden — Suspicious user agent blocked by FortressWP.');
            }
        }
    }

    public static function limit_login_attempts($user, $username, $password) {

        $opts = get_option(FortressWP::OPTION_KEY, []);
        $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        // Manual blocked usernames
        $manual_users = isset($opts['manual_block_users'])
            ? preg_split('/\r?\n/', $opts['manual_block_users'])
            : [];
        $manual_users = array_map('strtolower', array_filter(array_map('trim', $manual_users)));

        if ($username && in_array(strtolower($username), $manual_users, true)) {
            FW_Audit::log('login', 'Blocked username login attempt', [
                'user' => $username,
                'ip'   => $ip
            ], 'warning');
            return new WP_Error('fw_user_blocked', 'This account is blocked by FortressWP.');
        }

        if (is_wp_error($user) || !empty($user)) {
            return $user;
        }

        $max_attempts = intval($opts['max_login_attempts'] ?? 5);
        $lock_minutes = intval($opts['lockout_minutes'] ?? 15);

        $attempt_key = "fw_login_attempts_" . md5($ip);
        $lock_key    = "fw_login_locked_" . md5($ip);

        if (get_transient($lock_key)) {
            return new WP_Error(
                'fw_locked',
                'Too many failed login attempts. Try again later.'
            );
        }

        $user = wp_authenticate_username_password(null, $username, $password);

        if (is_wp_error($user)) {

            $attempts = intval(get_transient($attempt_key) ?: 0) + 1;
            set_transient($attempt_key, $attempts, $lock_minutes * 60);

            FW_Audit::log('login', 'Failed login attempt', [
                'user' => $username,
                'ip'   => $ip,
                'attempts' => $attempts
            ], 'notice');

            if ($attempts >= $max_attempts) {
                set_transient($lock_key, true, $lock_minutes * 60);
                FW_Audit::log('login', 'IP locked due to excessive failures', [
                    'ip' => $ip
                ], 'warning');
            }

            return $user;
        }

        delete_transient($attempt_key);
        delete_transient($lock_key);

        FW_Audit::log('login', 'Successful login', [
            'user' => $username,
            'ip'   => $ip
        ], 'info');

        return $user;
    }
}
