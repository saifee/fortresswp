<?php
if (!defined('ABSPATH')) exit;

class FW_Scanner {

    private static $inst;
    private $chunk_size = 50;
    const STATUS_OPT = 'fortresswp_scan_status';
    const ABORT_OPT = 'fortresswp_abort_scan';

    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    public function __construct() {
        $opts = get_option(FortressWP::OPTION_KEY, []);
        $this->chunk_size = max(5, intval($opts['scan_chunk_size'] ?? 50));

        add_action('wp_ajax_fortresswp_scan_status', [__CLASS__, 'ajax_scan_status']);
    }

    public static function queue_full_scan() {
        $self = self::instance();
        $self->run_immediate_scan();
    }

    public static function abort_scan() {
        update_option(self::ABORT_OPT, true);
        delete_option('fortresswp_scan_queue');
        FW_Audit::log('scan', 'Scan manually stopped by admin', array(), 'info');
    }

    /** Synchronous full scan (runs immediately) */
    private function run_immediate_scan() {

        $files = $this->gather_files_for_scan();
        $total = count($files);

        if ($total === 0) {
            update_option(self::STATUS_OPT, array(
                'total'        => 0,
                'processed'    => 0,
                'current_file' => '',
                'started_at'   => time(),
                'updated_at'   => time(),
                'done'         => true,
            ), false);
            return;
        }

        $status = array(
            'total'        => $total,
            'processed'    => 0,
            'current_file' => '',
            'started_at'   => time(),
            'updated_at'   => time(),
            'done'         => false,
        );
        update_option(self::STATUS_OPT, $status, false);

        foreach ($files as $file) {
            if (get_option(self::ABORT_OPT)) {
                delete_option(self::ABORT_OPT);
                FW_Audit::log('scan', 'Scan aborted by admin', array(), 'info');
                return;
            }
            $this->scan_file($file);
        }

        // Mark done
        $status = get_option(self::STATUS_OPT, array());
        if (is_array($status)) {
            $status['done']       = true;
            $status['updated_at'] = time();
            update_option(self::STATUS_OPT, $status, false);
        }

        FW_Audit::log('scan', 'Full scan completed', array(
            'total_files' => $total,
        ), 'info');
    }

    /** Scan ABSPATH + plugins + themes, skip uploads & large binaries */
    private function gather_files_for_scan() {

        $folders = array(
            ABSPATH,
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
        );

        $files = array();

        foreach ($folders as $dir) {
            if (!is_dir($dir)) continue;

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
            );

            foreach ($iterator as $file) {
                if (!$file->isFile()) continue;

                $path = $file->getPathname();

                // Skip uploads (usually media, large and not PHP)
                if (strpos($path, WP_CONTENT_DIR . '/uploads') === 0) continue;

                // Only scan reasonably sized files
                if (filesize($path) > 800000) continue; // 800KB

                $files[] = $path;
            }
        }

        return $files;
    }

    private function update_status_for_file($rel_file) {
        $st = get_option(self::STATUS_OPT, []);
        if (!is_array($st) || empty($st)) return;

        $st['processed']    = intval($st['processed'] ?? 0) + 1;
        $st['current_file'] = $rel_file;
        $st['updated_at']   = time();

        if ($st['processed'] >= ($st['total'] ?? 0)) {
            $st['done'] = true;
        }

        update_option(self::STATUS_OPT, $st, false);
    }

    private function scan_file($file) {
        if (get_option(self::ABORT_OPT)) return;
        
        if (!is_file($file)) return;

        $size = filesize($file);
        if ($size === false || $size > 800000) return;

        $content = @file_get_contents($file);
        if ($content === false) return;

        $rel_file = str_replace(ABSPATH, '', $file);

        // update progress status
        $this->update_status_for_file($rel_file);

        // 1. Signature detection
        $signatures = FW_Signature_Manager::get_signatures();
        foreach ($signatures as $sig) {
            if (!$sig) continue;
            if (stripos($content, $sig) !== false) {
                FW_Audit::log('scan', 'Signature match detected', [
                    'file' => $rel_file,
                    'sig'  => $sig
                ], 'warning');
            }
        }

        // 2. Heuristic detection
        if (preg_match('/(eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|shell_exec\s*\()/i', $content)) {
            $snippet = substr($content, 0, 3000);
            FW_Audit::log('scan', 'Heuristic suspicious pattern', [
                'file' => $rel_file
            ], 'notice');

            // 3. AI analysis
            $ai = FW_AIClient::instance();
            $result = $ai->analyze([
                'file'    => $rel_file,
                'snippet' => $snippet
            ]);
            FW_Audit::log('scan', 'AI analysis result', [
                'file'   => $rel_file,
                'result' => $result
            ], 'info');
        }
    }

    public static function ajax_start_scan() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('You do not have permission to run scans.');
        }
        check_ajax_referer('fortresswp_scan_nonce', 'nonce');
        self::queue_full_scan();
        wp_send_json_success('Scan started. Refresh status below.');
    }

    public static function ajax_scan_status() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied.');
        }

        $st = get_option(self::STATUS_OPT, []);
        if (!is_array($st) || empty($st)) {
            wp_send_json_success([
                'running' => false,
                'message' => 'No active scan.'
            ]);
        }

        $total     = intval($st['total'] ?? 0);
        $processed = intval($st['processed'] ?? 0);
        $current   = $st['current_file'] ?? '';
        $started   = intval($st['started_at'] ?? time());
        $now       = time();
        $elapsed   = max(1, $now - $started);
        $avg_per   = $processed > 0 ? $elapsed / $processed : null;
        $remaining = ($avg_per !== null && $total > $processed)
            ? (int) round(($total - $processed) * $avg_per)
            : null;

        $percent = $total > 0 ? round(($processed / $total) * 100, 1) : 0;

        wp_send_json_success([
            'running'      => !$st['done'],
            'done'         => (bool) $st['done'],
            'total'        => $total,
            'processed'    => $processed,
            'current_file' => $current,
            'elapsed'      => $elapsed,
            'remaining'    => $remaining,
            'percent'      => $percent,
        ]);
    }

    public static function ajax_abort_scan() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied.');
        }

        self::abort_scan();
        wp_send_json_success('Scan aborted.');
    }
}
