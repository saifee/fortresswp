<?php
if (!defined('ABSPATH')) exit;

class FW_AdminUI {

    private static $inst;

    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    public function __construct() {
        add_action('admin_menu', array($this, 'register_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }

    /** Load CSS + JS for admin panel */
    public function enqueue_assets($hook) {

        if (strpos($hook, 'fortresswp') === false) return;

        wp_enqueue_style(
            'fortresswp-admin',
            FORTRESSWP_URL . 'assets/css/admin.css',
            array(),
            FORTRESSWP_VERSION
        );

        wp_enqueue_script(
            'fortresswp-admin',
            FORTRESSWP_URL . 'assets/js/admin.js',
            array('jquery'),
            FORTRESSWP_VERSION,
            true
        );

        wp_localize_script('fortresswp-admin', 'fortresswp_admin', array(
            'scan_nonce' => wp_create_nonce('fortresswp_scan_nonce'),
            'totp_nonce' => wp_create_nonce('fortresswp_totp_nonce'),
            'ajax_url'   => admin_url('admin-ajax.php')
        ));
    }

    /** Register setting fields */
    public function register_settings() {
        register_setting(FortressWP::OPTION_KEY, FortressWP::OPTION_KEY, array($this, 'sanitize_settings'));
    }

    /** Basic sanitization */
    public function sanitize_settings($input) {
        $existing = get_option(FortressWP::OPTION_KEY, array());
        if (!is_array($existing)) $existing = array();

        foreach ($input as $k => $v) {
            switch ($k) {
                case 'ai_endpoint':
                case 'signature_sources':
                case 'blocklist_sources':
                case 'blocked_user_agents':
                    $existing[$k] = esc_textarea($v);
                    break;

                case 'ai_api_key':
                    $existing[$k] = sanitize_text_field($v);
                    break;

                case 'scan_chunk_size':
                case 'max_login_attempts':
                case 'lockout_minutes':
                    $existing[$k] = intval($v);
                    break;
            }
        }

        return $existing;
    }

    /** Create admin menu pages */
    public function register_menu() {

        add_menu_page(
            'FortressWP Security',
            'FortressWP',
            'manage_options',
            'fortresswp',
            array($this, 'page_dashboard'),
            'dashicons-shield'
        );

        add_submenu_page(
            'fortresswp',
            'TOTP Settings',
            'TOTP 2FA',
            'manage_options',
            'fortresswp_totp',
            array($this, 'page_totp')
        );
    }

    /** Dashboard page */
    public function page_dashboard() {
        if (!current_user_can('manage_options')) return;

        $opts = get_option(FortressWP::OPTION_KEY, []);

        ?>
        <div class="wrap fortresswp-wrap">

            <h1>FortressWP — Security Dashboard</h1>

            <form method="post" action="options.php">

                <?php settings_fields(FortressWP::OPTION_KEY); ?>

                <table class="form-table">

                    <tr>
                        <th><label>AI Endpoint</label></th>
                        <td>
                            <input type="url"
                                   name="<?php echo FortressWP::OPTION_KEY; ?>[ai_endpoint]"
                                   value="<?php echo esc_attr($opts['ai_endpoint'] ?? ''); ?>"
                                   class="regular-text">
                        </td>
                    </tr>

                    <tr>
                        <th><label>AI API Key</label></th>
                        <td>
                            <input type="password"
                                   name="<?php echo FortressWP::OPTION_KEY; ?>[ai_api_key]"
                                   value="<?php echo esc_attr($opts['ai_api_key'] ?? ''); ?>"
                                   class="regular-text">
                        </td>
                    </tr>

                    <tr>
                        <th>Signature Sources</th>
                        <td>
                            <textarea name="<?php echo FortressWP::OPTION_KEY; ?>[signature_sources]"
                                      rows="4" class="large-text code"><?php
                                echo esc_textarea($opts['signature_sources'] ?? '');
                                ?></textarea>
                        </td>
                    </tr>

                    <tr>
                        <th>Blocklist Sources</th>
                        <td>
                            <textarea name="<?php echo FortressWP::OPTION_KEY; ?>[blocklist_sources]"
                                      rows="4" class="large-text code"><?php
                                echo esc_textarea($opts['blocklist_sources'] ?? '');
                                ?></textarea>
                        </td>
                    </tr>

                    <tr>
                        <th>Scan Chunk Size</th>
                        <td>
                            <input type="number"
                                   name="<?php echo FortressWP::OPTION_KEY; ?>[scan_chunk_size]"
                                   value="<?php echo intval($opts['scan_chunk_size'] ?? 50); ?>"
                                   min="5" max="500">
                        </td>
                    </tr>

                    <tr>
                        <th>Max Login Attempts</th>
                        <td>
                            <input type="number"
                                   name="<?php echo FortressWP::OPTION_KEY; ?>[max_login_attempts]"
                                   value="<?php echo intval($opts['max_login_attempts'] ?? 5); ?>"
                                   min="1" max="20">
                        </td>
                    </tr>

                    <tr>
                        <th>Lockout Minutes</th>
                        <td>
                            <input type="number"
                                   name="<?php echo FortressWP::OPTION_KEY; ?>[lockout_minutes]"
                                   value="<?php echo intval($opts['lockout_minutes'] ?? 15); ?>"
                                   min="1" max="180">
                        </td>
                    </tr>

                    <tr>
                        <th>Blocked User Agents</th>
                        <td>
                            <textarea name="<?php echo FortressWP::OPTION_KEY; ?>[blocked_user_agents]"
                                      rows="4" class="large-text code"><?php
                                echo esc_textarea($opts['blocked_user_agents'] ?? '');
                                ?></textarea>
                        </td>
                    </tr>

                </table>

                <?php submit_button('Save Settings'); ?>

            </form>

            <hr>

            <h2>Security Tools</h2>

            <button id="fw-run-scan" class="button button-primary">Run Malware Scan</button>

            <button id="fw-update-sigs" class="button">Update Signatures</button>
            <button id="fw-update-blk" class="button">Update Blocklist</button>

            <pre id="fw-msg"></pre>

        </div>
        <?php
    }

    /** TOTP Page */
    public function page_totp() {

        if (!current_user_can('manage_options')) return;

        $user   = wp_get_current_user();
        $secret = get_user_meta($user->ID, 'fortresswp_totp_secret', true);

        if (!$secret) {
            $secret = FW_TOTP::generate_and_store($user->ID);
        }

        $otpauth = FW_TOTP::get_otpauth_url($user->user_login, $secret);
        $qr_url  = FW_TOTP::qr_code_url($otpauth);

        $backups = get_user_meta($user->ID, 'fortresswp_totp_backup', true);
        if (!is_array($backups)) $backups = [];

        ?>
        <div class="wrap fortresswp-wrap">
            <h1>TOTP Two-Factor Authentication</h1>

            <p>Scan this QR code with your authenticator app:</p>

            <img src="<?php echo esc_attr($qr_url); ?>" style="width:200px;height:200px;">

            <h3>Manual Secret</h3>
            <code><?php echo esc_html($secret); ?></code>

            <h3>Backup Codes</h3>
            <pre><?php echo esc_html(implode("\n", $backups)); ?></pre>

            <h3>Verify Code</h3>

            <form id="fw-verify-form">
                <input type="text" name="code" id="fw-totp-code">
                <button class="button">Verify</button>
            </form>

            <pre id="fw-verify-result"></pre>

        </div>

        <script>
        (function($){
            $('#fw-verify-form').on('submit', function(e){
                e.preventDefault();
                let fd = new FormData();
                fd.append('action','fortresswp_verify_totp');
                fd.append('code',$('#fw-totp-code').val());
                fd.append('nonce','<?php echo wp_create_nonce('fortresswp_totp_nonce'); ?>');

                fetch(ajaxurl,{method:'POST',body:fd})
                     .then(r=>r.json())
                     .then(j=>$('#fw-verify-result').text(JSON.stringify(j,null,2)));
            });
        })(jQuery);
        </script>
        <?php
    }

}
