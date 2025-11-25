<?php
if (!defined('ABSPATH')) exit;

class FW_Signature_Manager {

    private static $inst;

    const OPT_SIG = 'fortresswp_signatures';
    const OPT_BLK = 'fortresswp_blocklist';

    /** Singleton */
    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    private function __construct() {}

    /**
     * Fetch malware signatures from remote URLs
     * Normalize and store into database
     */
    public static function update_signatures() {

        $opts = get_option(FortressWP::OPTION_KEY, []);
        $sources = isset($opts['signature_sources'])
            ? preg_split('/\r?\n/', trim($opts['signature_sources']))
            : [];

        $collected = [];

        foreach ($sources as $src) {

            $src = trim($src);
            if (!$src) continue;

            $resp = wp_remote_get($src, ['timeout' => 20]);

            if (is_wp_error($resp)) {
                FW_Audit::log('signature', 'Failed to fetch signature feed', [
                    'source' => $src,
                    'error'  => $resp->get_error_message()
                ], 'warning');

                continue;
            }

            $body = wp_remote_retrieve_body($resp);

            $lines = preg_split('/\r?\n/', $body);

            foreach ($lines as $line) {
                $line = trim($line);
                if ($line !== '') {
                    $collected[$line] = true;
                }
            }
        }

        $final = array_keys($collected);

        update_option(self::OPT_SIG, $final);

        FW_Audit::log('signature', 'Signatures updated', [
            'count' => count($final)
        ], 'info');
    }

    /**
     * Fetch IP blocklist from remote sources
     */
    public static function update_blocklist() {

        $opts = get_option(FortressWP::OPTION_KEY, []);
        $sources = isset($opts['blocklist_sources'])
            ? preg_split('/\r?\n/', trim($opts['blocklist_sources']))
            : [];

        $ips = [];

        foreach ($sources as $src) {

            $src = trim($src);
            if (!$src) continue;

            $resp = wp_remote_get($src, ['timeout' => 20]);

            if (is_wp_error($resp)) {
                FW_Audit::log('blocklist', 'Failed to fetch blocklist feed', [
                    'source' => $src,
                    'error'  => $resp->get_error_message()
                ], 'warning');

                continue;
            }

            $body = wp_remote_retrieve_body($resp);

            $lines = preg_split('/\r?\n/', $body);

            foreach ($lines as $line) {
                $line = trim($line);

                if ($line && filter_var($line, FILTER_VALIDATE_IP)) {
                    $ips[$line] = true;
                }
            }
        }

        $final = implode("\n", array_keys($ips));

        update_option(self::OPT_BLK, $final);

        FW_Audit::log('blocklist', 'Blocklist updated', [
            'count' => count($ips)
        ], 'info');
    }

    /**
     * Return signatures as an array
     */
    public static function get_signatures() {
        $sigs = get_option(self::OPT_SIG, []);
        return is_array($sigs) ? $sigs : [];
    }

    /**
     * Return blocklisted IPs as an array
     */
    public static function get_blocklist() {

        $raw = get_option(self::OPT_BLK, '');

        $lines = array_filter(array_map('trim', explode("\n", $raw)));

        return $lines;
    }

}
