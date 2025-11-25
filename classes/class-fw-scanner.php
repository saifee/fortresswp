<?php
if (!defined('ABSPATH')) exit;

class FW_Scanner {

    private static $inst;
    private $chunk_size = 50;
    const STATUS_OPT = 'fortresswp_scan_status';

    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    public function __construct() {
        $opts = get_option(FortressWP::OPTION_KEY, []);
        $this->chunk_size = max(5, intval($opts['scan_chunk_size'] ?? 50));

        if (class_exists('ActionScheduler')) {
            add_action('fortresswp_as_chunk', [$this, 'as_process_chunk'], 10, 1);
        }
        add_action('fortresswp_process_cron_chunk', [$this, 'process_cron_chunk']);

        // status AJAX
        add_action('wp_ajax_fortresswp_scan_status', [__CLASS__, 'ajax_scan_status']);
    }

    public static function queue_full_scan() {

        $self  = self::instance();
        $files = $self->gather_files_for_scan();
        $total = count($files);

        if ($total === 0) return;

        // Initialize status
        $status = array(
            'total'        => $total,
            'processed'    => 0,
            'current_file' => '',
            'started_at'   => time(),
            'updated_at'   => time(),
            'done'         => false
        );
        update_option(self::STATUS_OPT, $status, false);

        if (class_exists('ActionScheduler') && function_exists('as_enqueue_async_action')) {
            $chunks = array_chunk($files, $self->chunk_size);
            foreach ($chunks as $i => $chunk) {
                as_enqueue_async_action('fortresswp_as_chunk', ['files' => $chunk, 'index' => $i]);
            }
            FW_Audit::log('scan', 'Scan queued via Action Scheduler', ['chunks' => count($chunks)]);
            return;
        }

        update_option(FortressWP::SCAN_QUEUE_KEY, $files);
        FW_Audit::log('scan', 'Scan queued via WP-Cron', ['files' => $total]);
    }

    public function as_process_chunk($args) {
        $files = $args['files'] ?? [];
        foreach ($files as $file) {
            $this->scan_file($file);
        }
        FW_Audit::log('scan', 'AS chunk processed', ['count' => count($files)]);
    }

    public function process_cron_chunk() {
        $queue = get_option(FortressWP::SCAN_QUEUE_KEY, []);
        if (empty($queue)) return;

        $chunk = array_splice($queue, 0, $this->chunk_size);
        foreach ($chunk as $file) {
            $this->scan_file($file);
        }

        if (empty($queue)) {
            delete_option(FortressWP::SCAN_QUEUE_KEY);
        } else {
            update_option(FortressWP::SCAN_QUEUE_KEY, $queue);
        }

        FW_Audit::log('scan', 'WP-Cron chunk processed', [
            'processed' => count($chunk),
            'remaining' => count($queue)
        ]);
    }

    private function gather_files_for_scan() {
        $folders = [
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
        ];

        $files = [];
        foreach ($folders as $dir) {
            if (!is_dir($dir)) continue;
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir)
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) continue;
                $path = $file->getPathname();
                if (filesize($path) <= 500000) {
                    $files[] = $path;
                }
            }
        }
        return $files;
    }

    private function update_status_for_file($rel_file) {
        $st = get_option(self::STATUS_OPT, []);
        if (!is_array($st) || empty($st)) return;

        $st['processed'] = intval($st['processed'] ?? 0) + 1;
        $st['current_file'] = $rel_file;
        $st['updated_at'] = time();

        if ($st['processed'] >= ($st['total'] ?? 0)) {
            $st['done'] = true;
        }

        update_option(self::STATUS_OPT, $st, false);
    }

    private function scan_file($file) {
        if (!is_file($file)) return;
        if (filesize($file) > 500000) return;

        $content = @file_get_contents($file);
        if ($content === false) return;

        $rel_file = str_replace(ABSPATH, '', $file);

        // update progress
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

        // 2. Heuristic pattern check
        if (preg_match('/(eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|shell_exec\s*\()/i', $content)) {
            $snippet = substr($content, 0, 3000);
            FW_Audit::log('scan', 'Heuristic suspicious pattern', ['file' => $rel_file], 'notice');

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
            wp_send_json_error(['message' => 'Permission denied']);
        }
        check_ajax_referer('fortresswp_scan_nonce', 'nonce');
        self::queue_full_scan();
        wp_send_json_success(['message' => 'Scan queued']);
    }

    public static function ajax_scan_status() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied']);
        }

        $st = get_option(self::STATUS_OPT, []);
        if (!is_array($st) || empty($st)) {
            wp_send_json_success([
                'running' => false
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
            'started_at'   => $started,
            'elapsed'      => $elapsed,
            'remaining'    => $remaining,
            'percent'      => $percent
        ]);
    }
}
