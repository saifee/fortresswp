<?php
/*
Plugin Name: FortressWP — by Saifullah Khalid & Kingslee Inc
Plugin URI: https://kingslee.net
Description: FortressWP security plugin (firewall, scanner, AI-assisted analysis, TOTP 2FA, signatures, blocklists).
Version: 1.2.1
Author: Saifullah Khalid (Kingslee Inc)
Author URI: mailto:me@saifullahkhalid.com
License: GPLv2 or later
Text Domain: fortresswp
*/

if (!defined('ABSPATH')) exit;

define('FORTRESSWP_VERSION', '1.2.1');
define('FORTRESSWP_DIR', plugin_dir_path(__FILE__));
define('FORTRESSWP_URL', plugin_dir_url(__FILE__));

if (!class_exists('FortressWP')) :

final class FortressWP {

    const OPTION_KEY     = 'fortresswp_options';
    const SIGNATURES_KEY = 'fortresswp_signatures';
    const BLOCKLIST_KEY  = 'fortresswp_blocklist';
    const SCAN_QUEUE_KEY = 'fortresswp_scan_queue';

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        $this->load_classes();
        register_activation_hook(__FILE__, array($this, 'on_activate'));
        register_deactivation_hook(__FILE__, array($this, 'on_deactivate'));
        add_action('init', array($this, 'init'), 1);
    }

    private function load_classes() {
        require_once FORTRESSWP_DIR . 'classes/class-fw-audit.php';
        require_once FORTRESSWP_DIR . 'classes/class-fw-firewall.php';
        require_once FORTRESSWP_DIR . 'classes/class-fw-signature-manager.php';
        require_once FORTRESSWP_DIR . 'classes/class-fw-scanner.php';
        require_once FORTRESSWP_DIR . 'classes/class-fw-aiclient.php';
        require_once FORTRESSWP_DIR . 'classes/class-fw-adminui.php';
        require_once FORTRESSWP_DIR . 'classes/class-fw-totp.php';
        require_once FORTRESSWP_DIR . 'classes/class-fw-ajax-sync.php';
    }

    /** Plugin activation: create defaults + schedule cron tasks **/
    public function on_activate() {
        $defaults = array(
            'admin_email'         => get_option('admin_email'),
            'ai_endpoint'         => '',
            'ai_api_key'          => '',
            'scan_chunk_size'     => 50,
            'signature_sources'   => '',
            'blocklist_sources'   => '',
            'max_login_attempts'  => 5,
            'lockout_minutes'     => 15,
            'blocked_user_agents' => "curl\nnikto\nacunetix\nsqlmap",
        );

        if (!get_option(self::OPTION_KEY)) {
            add_option(self::OPTION_KEY, $defaults);
        }

        if (!wp_next_scheduled('fortresswp_update_signatures')) {
            wp_schedule_event(time() + 60, 'daily', 'fortresswp_update_signatures');
        }
        if (!wp_next_scheduled('fortresswp_update_blocklist')) {
            wp_schedule_event(time() + 120, 'daily', 'fortresswp_update_blocklist');
        }
        if (!wp_next_scheduled('fortresswp_chunked_scan')) {
            wp_schedule_event(time() + 180, 'hourly', 'fortresswp_chunked_scan');
        }
    }

    /** Plugin deactivation */
    public function on_deactivate() {
        wp_clear_scheduled_hook('fortresswp_update_signatures');
        wp_clear_scheduled_hook('fortresswp_update_blocklist');
        wp_clear_scheduled_hook('fortresswp_chunked_scan');
    }

    /** Initialize all systems */
    public function init() {

        FW_Audit::instance();
        FW_Firewall::instance();
        FW_Signature_Manager::instance();
        FW_Scanner::instance();
        FW_AIClient::instance();
        FW_AdminUI::instance();
        FW_TOTP::instance();

        // Cron tasks
        add_action('fortresswp_update_signatures', array('FW_Signature_Manager', 'update_signatures'));
        add_action('fortresswp_update_blocklist', array('FW_Signature_Manager', 'update_blocklist'));
        add_action('fortresswp_chunked_scan', array('FW_Scanner', 'queue_full_scan'));

        // AJAX
        add_action('wp_ajax_fortresswp_start_scan', array('FW_Scanner','ajax_start_scan'));
        add_action('wp_ajax_fortresswp_verify_totp', array('FW_TOTP','ajax_verify_totp'));

        // Login limiter
        add_filter('authenticate', array('FW_Firewall','limit_login_attempts'), 30, 3);

        // Firewall early hook
        add_action('init', array('FW_Firewall','basic_firewall'), 1);
    }

}

FortressWP::instance();

endif;
