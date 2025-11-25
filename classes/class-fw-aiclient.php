<?php
if (!defined('ABSPATH')) exit;

class FW_AIClient {

    private static $inst;

    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    private function __construct() {}

    public function analyze($context) {

        $opts = get_option(FortressWP::OPTION_KEY, []);
        $provider = $opts['ai_provider'] ?? 'openai';
        $endpoint = trim($opts['ai_endpoint'] ?? '');
        $key      = trim($opts['ai_api_key'] ?? '');

        // Default endpoints based on provider
        if ($endpoint === '') {
            switch ($provider) {
                case 'openai':
                    $endpoint = 'https://api.openai.com/v1/chat/completions';
                    break;
                case 'openrouter':
                    $endpoint = 'https://openrouter.ai/api/v1/chat/completions';
                    break;
                case 'ollama':
                    $endpoint = 'http://localhost:11434/api/chat';
                    break;
                case 'kingslee':
                    $endpoint = 'https://api.kingslee.net/fortresswp/analyze';
                    break;
                case 'custom':
                default:
                    // require a custom endpoint
                    return array('error' => true, 'message' => 'Custom AI endpoint missing');
            }
        }

        if (!$endpoint) {
            return array('error' => true, 'message' => 'AI endpoint not configured');
        }

        if (!$key && $provider !== 'ollama' && $provider !== 'custom-noauth') {
            // assume keyless only for local/offline scenarios
            return array('error'=>true, 'message'=>'AI API key missing');
        }

        // Limit snippet length
        if (isset($context['snippet'])) {
            $context['snippet'] = substr($context['snippet'], 0, 3000);
        }

        $payload = json_encode(array(
            'action'   => 'malware_analysis',
            'language' => 'php',
            'data'     => $context,
        ));

        $headers = array('Content-Type' => 'application/json');
        if ($key) {
            $headers['Authorization'] = 'Bearer ' . $key;
        }

        $resp = wp_remote_post($endpoint, array(
            'timeout' => 25,
            'headers' => $headers,
            'body'    => $payload,
        ));

        if (is_wp_error($resp)) {
            return array('error' => true, 'message' => $resp->get_error_message());
        }

        $status = wp_remote_retrieve_response_code($resp);
        $body   = wp_remote_retrieve_body($resp);
        $decoded = json_decode($body, true);

        return array(
            'status'   => $status,
            'response' => $decoded ?: $body
        );
    }
}
