<?php
if (!defined('ABSPATH')) exit;

class FW_Firewall {

    private static $inst;

    /** Singleton */
    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    private function __construct() {}

    /**
     * BASIC FIREWALL
     * Runs early on init (priority 1)
     * Blocks:
     *  - Blacklisted IPs
     *  - Suspicious user agents
     */
    public static function basic_firewall() {

        $opts = get_option(FortressWP::OPTION_KEY, []);
        $ip   = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        /** 1. Blocklisted IPs */
        $blocklist = FW_Signature_Manager::get_blocklist();

        if ($ip && in_array($ip, $blocklist)) {
            FW_Audit::log('firewall', 'Blocked IP via blocklist', ['ip' => $ip], 'critical');
            status_header(403);
            wp_die('Forbidden – Your IP is blocked.');
        }

        /** 2. Block suspicious user agents */
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
                wp_die('Forbidden – Suspicious user agent.');
            }
        }
    }

    /**
     * LOGIN RATE LIMITING
     * Hooks into authenticate filter.
     */
    public static function limit_login_attempts($user, $username, $password) {

        // If WP already errored OR authenticated user is valid → do nothing
        if (is_wp_error($user) || !empty($user)) {
            return $user;
        }

        $opts = get_option(FortressWP::OPTION_KEY, []);
        $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        $max_attempts = intval($opts['max_login_attempts'] ?? 5);
        $lock_minutes = intval($opts['lockout_minutes'] ?? 15);

        $attempt_key = "fw_login_attempts_" . md5($ip);
        $lock_key    = "fw_login_locked_" . md5($ip);

        /** Check if IP is locked */
        if (get_transient($lock_key)) {
            return new WP_Error(
                'fw_locked',
                'Too many failed login attempts. Try again later.'
            );
        }

        /** Let WP verify username & password */
        $user = wp_authenticate_username_password(null, $username, $password);

        /** On failed login → increment attempts */
        if (is_wp_error($user)) {

            $attempts = intval(get_transient($attempt_key) ?: 0) + 1;
            set_transient($attempt_key, $attempts, $lock_minutes * 60);

            FW_Audit::log(
                'login',
                'Failed login attempt',
                ['user' => $username, 'ip' => $ip, 'attempts' => $attempts],
                'notice'
            );

            /** Lock IP if limit reached */
            if ($attempts >= $max_attempts) {
                set_transient($lock_key, true, $lock_minutes * 60);
                FW_Audit::log(
                    'login',
                    'IP locked due to excessive failures',
                    ['ip' => $ip],
                    'warning'
                );
            }

            return $user;
        }

        /** On successful login → reset counters */
        delete_transient($attempt_key);
        delete_transient($lock_key);

        FW_Audit::log('login', 'Successful login', ['user' => $username, 'ip' => $ip], 'info');

        return $user;
    }
}
