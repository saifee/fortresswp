<?php
/*
Plugin Name: FortressWP — by Saifullah Khalid & Kingslee Inc (Modular)
Plugin URI: https://kingslee.net
Description: FortressWP is an AI-powered WordPress security suite including Firewall, Malware Scan, Blocklists, TOTP 2FA, AI Code Analysis, Signature Updates, Login Protection, and Audit Logs.
Version: 2.2.2
Author: Saifullah Khalid (Kingslee Inc)
Author URI: mailto:me@saifullahkhalid.com
License: GPLv2 or later
Text Domain: fortresswp

Requires at least: 6.8
Tested up to: 6.8
Requires PHP: 8.2
*/

if (!defined('ABSPATH')) exit;

define('FORTRESSWP_VERSION', '1.2.2');
define('FORTRESSWP_PATH', plugin_dir_path(__FILE__));
define('FORTRESSWP_URL', plugin_dir_url(__FILE__));

if (!class_exists('FortressWP')):

final class FortressWP {

    const OPTION_KEY = 'fortresswp_mod_options';

    private static $inst = null;

    public static function instance() {
        if (self::$inst === null) {
            self::$inst = new self();
        }
        return self::$inst;
    }

    private function __construct() {
        $this->load_dependencies();
        $this->register_hooks();
    }

    private function load_dependencies() {

        require_once FORTRESSWP_PATH . 'classes/class-fw-adminui.php';
        require_once FORTRESSWP_PATH . 'classes/class-fw-aiclient.php';
        require_once FORTRESSWP_PATH . 'classes/class-fw-audit.php';
        require_once FORTRESSWP_PATH . 'classes/class-fw-firewall.php';
        require_once FORTRESSWP_PATH . 'classes/class-fw-scanner.php';
        require_once FORTRESSWP_PATH . 'classes/class-fw-signature-manager.php';
        require_once FORTRESSWP_PATH . 'classes/class-fw-totp.php';
        require_once FORTRESSWP_PATH . 'classes/class-fw-ajax-sync.php';
    }

    private function register_hooks() {
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        add_action('init', array($this, 'init'), 1);
    }

    public function activate() {

        $defaults = array(
            'ai_provider'        => 'openai',
            'ai_endpoint'        => 'https://api.openai.com/v1/chat/completions',
            'ai_api_key'         => '',
            'signature_sources'  => '',
            'blocklist_sources'  => '',
            'scan_chunk_size'    => 50,
            'max_login_attempts' => 5,
            'lockout_minutes'    => 15,
            'blocked_user_agents'=> '',
            'manual_block_ips'   => '',
            'manual_block_users' => ''
        );

        if (!get_option(self::OPTION_KEY)) {
            add_option(self::OPTION_KEY, $defaults);
        }

        // Schedule updates
        if (!wp_next_scheduled('fortresswp_update_signatures')) {
            wp_schedule_event(time() + 60, 'twicedaily', 'fortresswp_update_signatures');
        }

        if (!wp_next_scheduled('fortresswp_update_blocklist')) {
            wp_schedule_event(time() + 120, 'twicedaily', 'fortresswp_update_blocklist');
        }
    }

    public function deactivate() {
        wp_clear_scheduled_hook('fortresswp_update_signatures');
        wp_clear_scheduled_hook('fortresswp_update_blocklist');
    }

    public function init() {

        FW_Firewall::instance();
        FW_Scanner::instance();
        FW_AdminUI::instance();
        FW_AIClient::instance();
        FW_Audit::instance();
        FW_TOTP::instance();

        add_action('fortresswp_update_signatures', array('FW_Signature_Manager', 'update_signatures'));
        add_action('fortresswp_update_blocklist', array('FW_Signature_Manager', 'update_blocklist'));

        add_action('wp_ajax_fortresswp_start_scan', array('FW_Scanner', 'ajax_start_scan'));
        add_action('wp_ajax_fortresswp_scan_status', array('FW_Scanner', 'ajax_scan_status'));
        add_action('wp_ajax_fortresswp_abort_scan', array('FW_Scanner', 'ajax_abort_scan'));
        add_action('wp_ajax_fortresswp_verify_totp', array('FW_TOTP', 'ajax_verify_totp'));
    }
}

endif;

FortressWP::instance();
?>