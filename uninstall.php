<?php
// Exit if uninstall was not called from WordPress.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wll_settings' );
delete_option( 'wll_lockout_log' );
