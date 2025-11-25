<?php
if (!defined('ABSPATH')) exit;

/**
 * AJAX: Manual signature update
 */
add_action('wp_ajax_fortresswp_update_signatures_sync', function () {

    if (!current_user_can('manage_options')) {
        wp_send_json_error([
            'error'   => true,
            'message' => 'Permission denied'
        ]);
    }

    FW_Signature_Manager::update_signatures();

    wp_send_json_success([
        'success' => true,
        'message' => 'Signatures updated successfully'
    ]);
});

/**
 * AJAX: Manual blocklist update
 */
add_action('wp_ajax_fortresswp_update_blocklist_sync', function () {

    if (!current_user_can('manage_options')) {
        wp_send_json_error([
            'error'   => true,
            'message' => 'Permission denied'
        ]);
    }

    FW_Signature_Manager::update_blocklist();

    wp_send_json_success([
        'success' => true,
        'message' => 'Blocklist updated successfully'
    ]);
});
