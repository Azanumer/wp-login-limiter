<?php
/**
 * Plugin Name:       Login Limiter
 * Plugin URI:        https://github.com/Azanumer/wp-login-limiter
 * Description:       WordPress-native brute-force protection: lock an IP out after N failed logins, with an allow-list, lockout log and no fail2ban or server module required.
 * Version:           1.0.0
 * Author:            Azan Umer
 * License:           MIT
 * Text Domain:       wp-login-limiter
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WLL_VERSION', '1.0.0' );
define( 'WLL_OPTION', 'wll_settings' );

/**
 * Default settings.
 *
 * @return array
 */
function wll_get_settings() {
	$defaults = array(
		'max_attempts'   => 5,
		'window_minutes' => 15,
		'lockout_minutes' => 60,
		'allowlist'      => '',
	);
	$saved = get_option( WLL_OPTION, array() );
	return is_array( $saved ) ? array_merge( $defaults, $saved ) : $defaults;
}

/**
 * Visitor IP, honouring a trusted-proxy header only when the site owner
 * explicitly enables it via the wll_client_ip filter.
 *
 * @return string
 */
function wll_client_ip() {
	$ip = apply_filters( 'wll_client_ip', '' );
	if ( $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
		return $ip;
	}
	return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
}

/**
 * Is this IP on the allow-list? Supports single IPs and CIDR ranges.
 *
 * @param string $ip IP to check.
 * @return bool
 */
function wll_is_allowlisted( $ip ) {
	$settings = wll_get_settings();
	foreach ( preg_split( '/[\r\n,]+/', $settings['allowlist'] ) as $entry ) {
		$entry = trim( $entry );
		if ( '' === $entry ) {
			continue;
		}
		if ( false !== strpos( $entry, '/' ) ) {
			if ( wll_ip_in_cidr( $ip, $entry ) ) {
				return true;
			}
		} elseif ( $entry === $ip ) {
			return true;
		}
	}
	return false;
}

/**
 * IPv4 CIDR containment check.
 *
 * @param string $ip   IP address.
 * @param string $cidr CIDR range, e.g. 203.0.113.0/24.
 * @return bool
 */
function wll_ip_in_cidr( $ip, $cidr ) {
	list( $subnet, $bits ) = explode( '/', $cidr, 2 );
	$ip_long = ip2long( $ip );
	$subnet_long = ip2long( $subnet );
	if ( false === $ip_long || false === $subnet_long ) {
		return false;
	}
	$bits = (int) $bits;
	if ( $bits < 0 || $bits > 32 ) {
		return false;
	}
	$mask = 0 === $bits ? 0 : ( -1 << ( 32 - $bits ) );
	return ( $ip_long & $mask ) === ( $subnet_long & $mask );
}

/**
 * Transient keys for one IP's failure counter and lockout.
 *
 * @param string $ip IP address.
 * @return array
 */
function wll_keys( $ip ) {
	$hash = md5( $ip );
	return array(
		'attempts' => 'wll_attempts_' . $hash,
		'lockout'  => 'wll_lockout_' . $hash,
	);
}

/**
 * Block authentication while an IP is locked out.
 *
 * @param WP_User|WP_Error|null $user     Auth result so far.
 * @param string                $username Username attempted.
 * @param string                $password Password attempted.
 * @return WP_User|WP_Error|null
 */
function wll_authenticate( $user, $username, $password ) {
	if ( is_a( $user, 'WP_User' ) ) {
		return $user; // Already authenticated by an earlier filter.
	}
	$ip = wll_client_ip();
	if ( '' === $ip || wll_is_allowlisted( $ip ) ) {
		return $user;
	}
	$keys = wll_keys( $ip );
	$locked_until = get_transient( $keys['lockout'] );
	if ( $locked_until ) {
		return new WP_Error(
			'wll_locked_out',
			sprintf(
				/* translators: %d: minutes remaining in the lockout. */
				__( 'Too many failed login attempts. Try again in %d minutes.', 'wp-login-limiter' ),
				max( 1, (int) ceil( ( $locked_until - time() ) / 60 ) )
			)
		);
	}
	return $user;
}
add_filter( 'authenticate', 'wll_authenticate', 30, 3 );

/**
 * Record a failed login; lock the IP out once it crosses the threshold.
 *
 * @param string $username Username attempted.
 */
function wll_failed_login( $username ) {
	$ip = wll_client_ip();
	if ( '' === $ip || wll_is_allowlisted( $ip ) ) {
		return;
	}
	$settings = wll_get_settings();
	$keys = wll_keys( $ip );

	$attempts = (int) get_transient( $keys['attempts'] );
	$attempts++;
	set_transient( $keys['attempts'], $attempts, $settings['window_minutes'] * MINUTE_IN_SECONDS );

	if ( $attempts >= $settings['max_attempts'] ) {
		set_transient( $keys['lockout'], time() + $settings['lockout_minutes'] * MINUTE_IN_SECONDS, $settings['lockout_minutes'] * MINUTE_IN_SECONDS );
		delete_transient( $keys['attempts'] );

		$log = get_option( 'wll_lockout_log', array() );
		$log[] = array( 'ip' => $ip, 'username' => $username, 'time' => time() );
		update_option( 'wll_lockout_log', array_slice( $log, -100 ) ); // Keep the last 100.
	}
}
add_action( 'wp_login_failed', 'wll_failed_login' );

/**
 * Successful login resets the failure counter for that IP.
 *
 * @param string  $username Username.
 * @param WP_User $user     User object.
 */
function wll_successful_login( $username, $user ) {
	$ip = wll_client_ip();
	if ( '' === $ip ) {
		return;
	}
	$keys = wll_keys( $ip );
	delete_transient( $keys['attempts'] );
}
add_action( 'wp_login', 'wll_successful_login', 10, 2 );

/**
 * Settings page under Settings → Login Limiter.
 */
function wll_register_settings_page() {
	add_options_page(
		__( 'Login Limiter', 'wp-login-limiter' ),
		__( 'Login Limiter', 'wp-login-limiter' ),
		'manage_options',
		'wll-settings',
		'wll_render_settings_page'
	);
}
add_action( 'admin_menu', 'wll_register_settings_page' );

/**
 * Register the option with sanitisation.
 */
function wll_register_settings() {
	register_setting(
		'wll_settings_group',
		WLL_OPTION,
		array(
			'type'              => 'array',
			'sanitize_callback' => 'wll_sanitize_settings',
			'default'           => array(),
		)
	);
}
add_action( 'admin_init', 'wll_register_settings' );

/**
 * Sanitise settings input.
 *
 * @param array $input Raw input.
 * @return array
 */
function wll_sanitize_settings( $input ) {
	$clean = array();
	$clean['max_attempts'] = max( 1, (int) ( $input['max_attempts'] ?? 5 ) );
	$clean['window_minutes'] = max( 1, (int) ( $input['window_minutes'] ?? 15 ) );
	$clean['lockout_minutes'] = max( 1, (int) ( $input['lockout_minutes'] ?? 60 ) );
	$clean['allowlist'] = isset( $input['allowlist'] ) ? sanitize_textarea_field( wp_unslash( $input['allowlist'] ) ) : '';
	return $clean;
}

/**
 * Render the settings page, including the recent lockout log.
 */
function wll_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'wp-login-limiter' ) );
	}
	$settings = wll_get_settings();
	$log = array_reverse( (array) get_option( 'wll_lockout_log', array() ) );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'Login Limiter', 'wp-login-limiter' ); ?></h1>
		<p><?php esc_html_e( 'After the configured number of failed logins inside the window, the IP is locked out for the lockout period. Successful logins reset the counter.', 'wp-login-limiter' ); ?></p>
		<form method="post" action="options.php">
			<?php settings_fields( 'wll_settings_group' ); ?>
			<table class="form-table">
				<tr>
					<th scope="row"><label for="wll-max"><?php esc_html_e( 'Max failed attempts', 'wp-login-limiter' ); ?></label></th>
					<td><input id="wll-max" type="number" min="1" name="<?php echo esc_attr( WLL_OPTION ); ?>[max_attempts]" value="<?php echo esc_attr( $settings['max_attempts'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><label for="wll-window"><?php esc_html_e( 'Counting window (minutes)', 'wp-login-limiter' ); ?></label></th>
					<td><input id="wll-window" type="number" min="1" name="<?php echo esc_attr( WLL_OPTION ); ?>[window_minutes]" value="<?php echo esc_attr( $settings['window_minutes'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><label for="wll-lockout"><?php esc_html_e( 'Lockout duration (minutes)', 'wp-login-limiter' ); ?></label></th>
					<td><input id="wll-lockout" type="number" min="1" name="<?php echo esc_attr( WLL_OPTION ); ?>[lockout_minutes]" value="<?php echo esc_attr( $settings['lockout_minutes'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><label for="wll-allowlist"><?php esc_html_e( 'Allow-listed IPs / CIDR ranges (one per line)', 'wp-login-limiter' ); ?></label></th>
					<td><textarea id="wll-allowlist" rows="4" cols="40" name="<?php echo esc_attr( WLL_OPTION ); ?>[allowlist]"><?php echo esc_textarea( $settings['allowlist'] ); ?></textarea></td>
				</tr>
			</table>
			<?php submit_button(); ?>
		</form>

		<h2><?php esc_html_e( 'Recent lockouts', 'wp-login-limiter' ); ?></h2>
		<?php if ( empty( $log ) ) : ?>
			<p><?php esc_html_e( 'No lockouts recorded yet.', 'wp-login-limiter' ); ?></p>
		<?php else : ?>
			<table class="widefat striped">
				<thead><tr><th><?php esc_html_e( 'IP', 'wp-login-limiter' ); ?></th><th><?php esc_html_e( 'Username tried', 'wp-login-limiter' ); ?></th><th><?php esc_html_e( 'Time', 'wp-login-limiter' ); ?></th></tr></thead>
				<tbody>
				<?php foreach ( $log as $entry ) : ?>
					<tr>
						<td><?php echo esc_html( $entry['ip'] ); ?></td>
						<td><?php echo esc_html( $entry['username'] ); ?></td>
						<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $entry['time'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		<?php endif; ?>
	</div>
	<?php
}
