<?php
if (!defined('WP_UNINSTALL_PLUGIN')) exit;

// Remove options
delete_option('fortresswp_options');
delete_option('fortresswp_signatures');
delete_option('fortresswp_blocklist');
delete_option('fortresswp_scan_queue');
delete_option('fortresswp_audit_log');

// Remove usermeta (TOTP)
global $wpdb;
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = 'fortresswp_totp_secret'");
$wpdb->query("DELETE FROM {$wpdb->usermeta} WHERE meta_key = 'fortresswp_totp_backup'");
