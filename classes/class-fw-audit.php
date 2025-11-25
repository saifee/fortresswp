<?php
if (!defined('ABSPATH')) exit;

class FW_Audit {

    const OPTION_KEY = 'fortresswp_audit_log';

    private static $inst;

    /** Singleton */
    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    private function __construct() {}

    /**
     * Add an audit log entry
     *
     * @param string $type     (firewall, login, scan, totp, ai, system)
     * @param string $message
     * @param array  $meta     (additional info)
     * @param string $severity (info|notice|warning|critical)
     */
    public static function log($type, $message, $meta = [], $severity = 'info') {

        $logs = get_option(self::OPTION_KEY, []);

        if (!is_array($logs)) {
            $logs = [];
        }

        $logs[] = [
            'time'     => current_time('mysql'),
            'type'     => $type,
            'message'  => $message,
            'meta'     => $meta,
            'severity' => $severity,
            'ip'       => $_SERVER['REMOTE_ADDR'] ?? '',
            'user'     => wp_get_current_user()->user_login ?? 'guest'
        ];

        // Keep only the last 2000 logs
        if (count($logs) > 2000) {
            $logs = array_slice($logs, -2000);
        }

        update_option(self::OPTION_KEY, $logs);
    }

    /**
     * Return recent N logs
     */
    public static function get_recent($limit = 200) {
        $logs = get_option(self::OPTION_KEY, []);
        if (!is_array($logs)) return [];
        return array_slice($logs, -$limit);
    }

    /**
     * Clear all logs
     */
    public static function clear() {
        update_option(self::OPTION_KEY, []);
    }
}
