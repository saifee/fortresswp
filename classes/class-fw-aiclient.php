<?php
if (!defined('ABSPATH')) exit;

class FW_AIClient {

    private static $inst;

    /** Singleton */
    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    private function __construct() {}

    /**
     * Analyze suspicious code using external AI API.
     * Payload is always sanitized & limited.
     *
     * @param array $context  (file name, snippet, metadata)
     * @return array|string
     */
    public function analyze($context) {

        $opts     = get_option(FortressWP::OPTION_KEY, []);
        $endpoint = trim($opts['ai_endpoint'] ?? '');
        $key      = trim($opts['ai_api_key'] ?? '');

        if (!$endpoint || !$key) {
            return [
                'error'   => true,
                'message' => 'AI endpoint or API key missing'
            ];
        }

        // Limit snippet size for safety + cost control
        if (isset($context['snippet'])) {
            $context['snippet'] = substr($context['snippet'], 0, 3000);
        }

        $payload = json_encode([
            'action'   => 'malware_analysis',
            'language' => 'php',
            'data'     => $context,
        ]);

        $resp = wp_remote_post($endpoint, [
            'timeout' => 25,
            'headers' => [
                'Content-Type'  => 'application/json',
                'Authorization' => 'Bearer ' . $key
            ],
            'body' => $payload
        ]);

        if (is_wp_error($resp)) {
            return [
                'error'   => true,
                'message' => $resp->get_error_message()
            ];
        }

        $status = wp_remote_retrieve_response_code($resp);
        $body   = wp_remote_retrieve_body($resp);

        $decoded = json_decode($body, true);

        return [
            'status'   => $status,
            'response' => $decoded ? $decoded : $body
        ];
    }
}
