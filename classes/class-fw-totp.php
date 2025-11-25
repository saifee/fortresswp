<?php
if (!defined('ABSPATH')) exit;

class FW_TOTP {

    private static $inst;

    /** Singleton */
    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    private function __construct() {}

    /**
     * Generate a Base32 secret
     */
    public static function generate_secret($length = 16) {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';

        for ($i = 0; $i < $length; $i++) {
            $secret .= $chars[random_int(0, strlen($chars) - 1)];
        }

        return $secret;
    }

    /**
     * Generate and store the secret + backup codes
     */
    public static function generate_and_store($user_id) {

        $secret = self::generate_secret();

        update_user_meta($user_id, 'fortresswp_totp_secret', $secret);

        $codes = self::generate_backup_codes();
        update_user_meta($user_id, 'fortresswp_totp_backup', $codes);

        return $secret;
    }

    /**
     * Backup codes in case user loses authenticator
     */
    public static function generate_backup_codes($count = 6) {

        $codes = [];

        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtoupper(bin2hex(random_bytes(3))); // 6 chars
        }

        return $codes;
    }

    /**
     * Minimal Base32 decoder (RFC4648)
     */
    private static function base32_decode($b32) {

        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

        $b32 = strtoupper($b32);
        $length = strlen($b32);
        $n = 0;
        $j = 0;
        $binary = '';

        for ($i = 0; $i < $length; $i++) {

            $n = ($n << 5) + strpos($alphabet, $b32[$i]);
            $j += 5;

            if ($j >= 8) {
                $j -= 8;
                $binary .= chr(($n & (0xFF << $j)) >> $j);
            }
        }

        return $binary;
    }

    /**
     * HOTP (HMAC-based One-Time Password)
     */
    private static function hotp($secret, $counter) {

        $key = self::base32_decode($secret);

        $bin_counter = pack('N*', 0) . pack('N*', $counter);

        $hash = hash_hmac('sha1', $bin_counter, $key, true);

        $offset = ord(substr($hash, -1)) & 0x0F;

        $truncated = unpack('N', substr($hash, $offset, 4));
        $truncated = $truncated[1] & 0x7FFFFFFF;

        return $truncated % 1000000;
    }

    /**
     * TOTP = HOTP with a time counter (RFC-6238)
     */
    public static function totp($secret, $timeSlice = null) {

        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30); // 30 second window
        }

        return str_pad(self::hotp($secret, $timeSlice), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verify time-based code (±$window drift)
     */
    public static function verify_code($secret, $code, $window = 1) {

        $code = str_pad($code, 6, '0', STR_PAD_LEFT);
        $timeSlice = floor(time() / 30);

        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals(self::totp($secret, $timeSlice + $i), $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Create otpauth:// URI
     */
    public static function get_otpauth_url($user, $secret, $issuer = 'FortressWP') {

        $label = rawurlencode($issuer . ':' . $user);

        return "otpauth://totp/{$label}?secret={$secret}&issuer=" . rawurlencode($issuer);
    }

    /**
     * Generate QR code URL using Google Charts API
     * (optional: can replace with a local QR library)
     */
   public static function qr_code_url($otpauth, $size = 200) {
    $s = intval($size);
    return 'https://api.qrserver.com/v1/create-qr-code/?size=' . $s . 'x' . $s . '&data=' . rawurlencode($otpauth);
}


    /**
     * AJAX endpoint — verify TOTP or backup code
     */
    public static function ajax_verify_totp() {

        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied.');
        }

        check_ajax_referer('fortresswp_totp_nonce', 'nonce', true);

        $user  = wp_get_current_user();
        $secret = get_user_meta($user->ID, 'fortresswp_totp_secret', true);

        if (!$secret) {
            wp_send_json_error('No secret found for user.');
        }

        $code = sanitize_text_field($_POST['code'] ?? '');

        /** 1. Verify TOTP token */
        if (self::verify_code($secret, $code)) {

            FW_Audit::log('totp', 'TOTP verified', [
                'user' => $user->user_login
            ], 'info');

            wp_send_json_success('totp_ok');
        }

        /** 2. Check backup codes */
        $backups = get_user_meta($user->ID, 'fortresswp_totp_backup', true);

        if (!is_array($backups)) $backups = [];

        $upper = strtoupper($code);

        $index = array_search($upper, $backups);

        if ($index !== false) {

            unset($backups[$index]);
            update_user_meta($user->ID, 'fortresswp_totp_backup', $backups);

            FW_Audit::log('totp', 'Backup code used', [
                'user' => $user->user_login
            ], 'notice');

            wp_send_json_success('backup_ok');
        }

        wp_send_json_error('invalid_code');
    }
}
