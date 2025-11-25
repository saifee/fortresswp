<?php
if (!defined('ABSPATH')) exit;

class FW_Scanner {

    private static $inst;
    private $chunk_size = 50;

    /** Singleton */
    public static function instance() {
        if (!self::$inst) self::$inst = new self();
        return self::$inst;
    }

    public function __construct() {

        // Load chunk size from settings
        $opts = get_option(FortressWP::OPTION_KEY, []);
        $this->chunk_size = max(5, intval($opts['scan_chunk_size'] ?? 50));

        // Action Scheduler integration
        if (class_exists('ActionScheduler')) {
            add_action('fortresswp_as_chunk', [$this, 'as_process_chunk'], 10, 1);
        }

        // WP Cron fallback
        add_action('fortresswp_process_cron_chunk', [$this, 'process_cron_chunk']);
    }

    /**
     * MAIN ENTRY — Queue a full scan
     * Splits file list into chunks
     */
    public static function queue_full_scan() {

        $self  = self::instance();
        $files = $self->gather_files_for_scan();

        if (empty($files)) return;

        // Action Scheduler take priority
        if (class_exists('ActionScheduler') && function_exists('as_enqueue_async_action')) {

            $chunks = array_chunk($files, $self->chunk_size);

            foreach ($chunks as $i => $chunk) {
                as_enqueue_async_action(
                    'fortresswp_as_chunk',
                    ['files' => $chunk, 'index' => $i]
                );
            }

            FW_Audit::log('scan', 'Scan queued via Action Scheduler', [
                'chunks' => count($chunks)
            ]);

            return;
        }

        // WP Cron fallback
        update_option(FortressWP::SCAN_QUEUE_KEY, $files);

        FW_Audit::log('scan', 'Scan queued via WP-Cron', [
            'files' => count($files)
        ]);
    }

    /**
     * Action Scheduler worker — processes a chunk
     */
    public function as_process_chunk($args) {

        $files = $args['files'] ?? [];

        foreach ($files as $file) {
            $this->scan_file($file);
        }

        FW_Audit::log('scan', 'AS chunk processed', [
            'count' => count($files)
        ]);
    }

    /**
     * WP Cron worker — processes one chunk
     */
    public function process_cron_chunk() {

        $queue = get_option(FortressWP::SCAN_QUEUE_KEY, []);

        if (empty($queue)) return;

        $chunk = array_splice($queue, 0, $this->chunk_size);

        foreach ($chunk as $file) {
            $this->scan_file($file);
        }

        // Save remaining queue
        if (empty($queue)) {
            delete_option(FortressWP::SCAN_QUEUE_KEY);
        } else {
            update_option(FortressWP::SCAN_QUEUE_KEY, $queue);
        }

        FW_Audit::log('scan', 'WP-Cron chunk processed', [
            'processed'  => count($chunk),
            'remaining'  => count($queue)
        ]);
    }

    /**
     * Gathers all plugin/theme PHP files for scanning
     */
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

                // Only scan small to medium files
                if (filesize($path) <= 500000) {  // 500 KB
                    $files[] = $path;
                }
            }
        }

        return $files;
    }

    /**
     * Scans a single file for malware
     */
    private function scan_file($file) {

        if (!is_file($file)) return;

        $content = @file_get_contents($file);

        if ($content === false) return;

        $rel_file = str_replace(ABSPATH, '', $file);

        /** 1. Signature detection */
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

        /** 2. Heuristic detection */
        if (preg_match('/(eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|shell_exec\s*\()/i', $content)) {

            $snippet = substr($content, 0, 3000); // Take start of file

            FW_Audit::log('scan', 'Heuristic suspicious pattern found', [
                'file' => $rel_file
            ], 'notice');

            /** 3. AI-assisted analysis */
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

    /**
     * AJAX — admin manual scan
     */
    public static function ajax_start_scan() {

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied']);
        }

        check_ajax_referer('fortresswp_scan_nonce', 'nonce');

        self::queue_full_scan();

        wp_send_json_success(['message' => 'Scan queued']);
    }
}
