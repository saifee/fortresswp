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

        $opts = get_option(FortressWP::OPTION_KEY, array());
        $provider = $opts['ai_provider'] ?? 'openai';

        wp_localize_script('fortresswp-admin', 'fortresswp_admin', array(
            'scan_nonce'  => wp_create_nonce('fortresswp_scan_nonce'),
            'totp_nonce'  => wp_create_nonce('fortresswp_totp_nonce'),
            'ajax_url'    => admin_url('admin-ajax.php'),
            'ai_provider' => $provider,
            'ai_endpoint' => $opts['ai_endpoint'] ?? '',
        ));
    }

    public function register_settings() {
        register_setting(FortressWP::OPTION_KEY, FortressWP::OPTION_KEY, array($this, 'sanitize_settings'));
    }

    public function sanitize_settings($input) {
        $existing = get_option(FortressWP::OPTION_KEY, array());
        if (!is_array($existing)) $existing = array();

        $keys_text   = array('ai_api_key');
        $keys_textarea = array('signature_sources','blocklist_sources','blocked_user_agents','manual_block_ips','manual_block_users');
        $keys_int    = array('scan_chunk_size','max_login_attempts','lockout_minutes');
        $keys_select = array('ai_provider');

        foreach ($input as $k => $v) {

            if (in_array($k, $keys_text, true)) {
                $existing[$k] = sanitize_text_field($v);
            } elseif (in_array($k, $keys_int, true)) {
                $existing[$k] = intval($v);
            } elseif (in_array($k, $keys_textarea, true)) {
                $existing[$k] = esc_textarea($v);
            } elseif (in_array($k, $keys_select, true)) {
                $allowed_providers = array('openai','openrouter','ollama','kingslee','custom');
                $v = sanitize_text_field($v);
                $existing[$k] = in_array($v, $allowed_providers, true) ? $v : 'openai';
            } elseif ($k === 'ai_endpoint') {
                $existing[$k] = esc_url_raw($v);
            }
        }

        return $existing;
    }

    public function register_menu() {
        add_menu_page(
            'FortressWP Security',
            'FortressWP',
            'manage_options',
            'fortresswp_dashboard',
            array($this, 'page_dashboard'),
            'dashicons-shield'
        );

        add_submenu_page(
            'fortresswp_dashboard',
            'FortressWP Dashboard',
            'Dashboard',
            'manage_options',
            'fortresswp_dashboard',
            array($this, 'page_dashboard')
        );

        add_submenu_page(
            'fortresswp_dashboard',
            'Malware Scan',
            'Scan',
            'manage_options',
            'fortresswp_scan',
            array($this, 'page_scan')
        );

        add_submenu_page(
            'fortresswp_dashboard',
            'Firewall & Blocking',
            'Firewall',
            'manage_options',
            'fortresswp_firewall',
            array($this, 'page_firewall')
        );

        add_submenu_page(
            'fortresswp_dashboard',
            'Scan Reports',
            'Reports',
            'manage_options',
            'fortresswp_reports',
            array($this, 'page_reports')
        );

        add_submenu_page(
            'fortresswp_dashboard',
            'TOTP 2FA',
            'TOTP 2FA',
            'manage_options',
            'fortresswp_totp',
            array($this, 'page_totp')
        );

        add_submenu_page(
            'fortresswp_dashboard',
            'Settings',
            'Settings',
            'manage_options',
            'fortresswp_settings',
            array($this, 'page_settings')
        );
    }

    /* ========== PAGES ========== */

    public function page_dashboard() {
        if (!current_user_can('manage_options')) return; ?>
        <div class="wrap fortresswp-wrap">
            <h1>FortressWP — Dashboard</h1>
            <p>Welcome to FortressWP. Use the Scan, Firewall, Reports, TOTP 2FA, and Settings tabs from the menu.</p>
        </div>
        <?php
    }

    public function page_settings() {
        if (!current_user_can('manage_options')) return;
        $opts = get_option(FortressWP::OPTION_KEY, array());
        $provider = $opts['ai_provider'] ?? 'openai';
        ?>
        <div class="wrap fortresswp-wrap">
            <h1>FortressWP — Settings</h1>

            <form method="post" action="options.php">
            <?php settings_fields(FortressWP::OPTION_KEY); ?>
            <table class="form-table">

                <tr>
                    <th scope="row"><label for="fw-ai-provider">AI Provider</label></th>
                    <td>
                        <select id="fw-ai-provider" name="<?php echo FortressWP::OPTION_KEY; ?>[ai_provider]">
                            <option value="openai"   <?php selected($provider,'openai'); ?>>OpenAI (ChatGPT)</option>
                            <option value="openrouter" <?php selected($provider,'openrouter'); ?>>OpenRouter / Compatible API</option>
                            <option value="ollama"   <?php selected($provider,'ollama'); ?>>Local Ollama Server</option>
                            <option value="kingslee" <?php selected($provider,'kingslee'); ?>>Kingslee AI Cloud</option>
                            <option value="custom"   <?php selected($provider,'custom'); ?>>Custom Endpoint</option>
                        </select>
                        <p class="description">Choose which AI backend to use for malware analysis.</p>
                    </td>
                </tr>

                <tr>
                    <th scope="row"><label for="fw-ai-endpoint">AI Endpoint</label></th>
                    <td>
                        <input type="url"
                               id="fw-ai-endpoint"
                               name="<?php echo FortressWP::OPTION_KEY; ?>[ai_endpoint]"
                               class="regular-text"
                               value="<?php echo esc_attr($opts['ai_endpoint'] ?? ''); ?>">
                        <p class="description">
                            For non-custom providers this will auto-fill. Only editable when "Custom Endpoint" is selected.
                        </p>
                    </td>
                </tr>

                <tr>
                    <th scope="row"><label for="fw-ai-key">AI API Key</label></th>
                    <td>
                        <input type="password"
                               id="fw-ai-key"
                               name="<?php echo FortressWP::OPTION_KEY; ?>[ai_api_key]"
                               class="regular-text"
                               value="<?php echo esc_attr($opts['ai_api_key'] ?? ''); ?>">
                        <p class="description">Your AI provider API key (e.g., OpenAI secret key).</p>
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
        </div>
        <?php
    }

    public function page_scan() {
        if (!current_user_can('manage_options')) return;
        ?>
        <div class="wrap fortresswp-wrap">
            <h1>FortressWP — Malware Scanner</h1>

            <p>Run a full scan of your WordPress root, plugins and themes. Progress will be displayed below.</p>

            <button id="fw-run-scan" class="button button-primary">Start Scan</button>
            <button id="fw-update-sigs" class="button">Update Signatures</button>
            <button id="fw-update-blk" class="button">Update Blocklist</button>

            <div id="fw-scan-progress-wrapper">
                <div id="fw-scan-progress-bar"><span id="fw-scan-progress-fill"></span></div>
                <div id="fw-scan-stats">
                    <span id="fw-scan-count"></span>
                    <span id="fw-scan-time"></span>
                </div>
                <div>Current file: <span id="fw-scan-current"></span></div>
            </div>

            <div id="fw-msg" class="fw-msg"></div>
        </div>
        <?php
    }

    public function page_firewall() {
        if (!current_user_can('manage_options')) return;
        $opts = get_option(FortressWP::OPTION_KEY, array());
        ?>
        <div class="wrap fortresswp-wrap">
            <h1>FortressWP — Firewall & Blocking</h1>

            <form method="post" action="options.php">
            <?php settings_fields(FortressWP::OPTION_KEY); ?>

            <h2>Manual IP Block List</h2>
            <p>Each IP on a separate line. These IPs will always be blocked.</p>
            <textarea name="<?php echo FortressWP::OPTION_KEY; ?>[manual_block_ips]"
                      rows="8" class="large-text code"><?php
                echo esc_textarea($opts['manual_block_ips'] ?? '');
            ?></textarea>

            <h2>Blocked Usernames</h2>
            <p>Each username on a separate line. These users will always be denied login.</p>
            <textarea name="<?php echo FortressWP::OPTION_KEY; ?>[manual_block_users]"
                      rows="8" class="large-text code"><?php
                echo esc_textarea($opts['manual_block_users'] ?? '');
            ?></textarea>

            <?php submit_button('Save Firewall Rules'); ?>
            </form>
        </div>
        <?php
    }

    public function page_reports() {
        if (!current_user_can('manage_options')) return;

        $logs = FW_Audit::get_recent(300);
        // filter only scan-related logs
        $scan_logs = array_filter($logs, function($row){
            return isset($row['type']) && $row['type'] === 'scan';
        });
        ?>
        <div class="wrap fortresswp-wrap">
            <h1>FortressWP — Scan Reports</h1>
            <p>Below are recent scan events with as much detail as possible.</p>

            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Message</th>
                        <th>Severity</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($scan_logs)) : ?>
                    <tr><td colspan="4">No scan reports yet.</td></tr>
                <?php else : ?>
                    <?php foreach ($scan_logs as $row) : ?>
                        <tr>
                            <td><?php echo esc_html($row['time'] ?? ''); ?></td>
                            <td><?php echo esc_html($row['message'] ?? $row['msg'] ?? ''); ?></td>
                            <td><?php echo esc_html($row['severity'] ?? 'info'); ?></td>
                            <td>
                                <pre><?php echo esc_html(print_r($row['meta'] ?? array(), true)); ?></pre>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    public function page_totp() {
        if (!current_user_can('manage_options')) return;

        $user   = wp_get_current_user();
        $secret = get_user_meta($user->ID, 'fortresswp_totp_secret', true);
        if (!$secret) {
            $secret = FW_TOTP::generate_and_store($user->ID);
        }

        $otpauth = FW_TOTP::get_otpauth_url($user->user_login, $secret);
        $qr_url  = FW_TOTP::qr_code_url($otpauth);
        $codes   = get_user_meta($user->ID, 'fortresswp_totp_backup', true);
        if (!is_array($codes)) $codes = array();
        ?>
        <div class="wrap fortresswp-wrap">
            <h1>FortressWP — TOTP 2FA</h1>

            <p>Scan this QR in Google Authenticator / Authy:</p>
            <img src="<?php echo esc_attr($qr_url); ?>" width="200" height="200" alt="TOTP QR">

            <h3>Manual Secret</h3>
            <code><?php echo esc_html($secret); ?></code>

            <h3>Backup Codes</h3>
            <pre><?php echo esc_html(implode("\n", $codes)); ?></pre>

            <h3>Verify Code</h3>
            <form id="fw-verify-form">
                <input type="text" name="code" id="fw-totp-code">
                <button class="button">Verify</button>
            </form>

            <pre id="fw-verify-result"></pre>
        </div>
        <?php
    }
}
