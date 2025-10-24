<?php
/**
 * Plugin Name:     Device-Limit Login (Single Device)
 * Plugin URI:      https://github.com/mdniajm/device-limit-login/
 * Description:     Limits each non-admin user to a single device/browser and blocks all other logins. Creates an Access Denied page and forces blocked users to it.
 * Version:         1.1.0
 * Author:          Md. Niaj Makhdum
 * Author URI:      https://mdniajmakhdum.me
 * Text Domain:     device-limit-login
 * License:         GPL-2.0-or-later
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Composer autoload (DeviceDetector). Safe-guarded for first installs w/o vendor present.
 */
$dl_vendor = __DIR__ . '/vendor/autoload.php';
if ( file_exists( $dl_vendor ) ) {
    require_once $dl_vendor;
}

use DeviceDetector\DeviceDetector;
use DeviceDetector\Parser\Device\AbstractDeviceParser;

/**
 * === Helpers ===
 */

/**
 * Option key for the Access Denied page ID.
 */
function dl_option_page_id_key() {
    return 'dl_access_denied_page_id';
}

/**
 * Get the Access Denied permalink, falling back to /access-denied.
 */
function dl_get_denied_url() {
    $page_id = (int) get_option( dl_option_page_id_key() );
    if ( $page_id ) {
        $url = get_permalink( $page_id );
        if ( $url ) {
            return $url;
        }
    }
    return home_url( '/access-denied' );
}

/**
 * Build a unique device identifier from the user-agent.
 */
function dl_get_device_id() {
    if ( ! class_exists( DeviceDetector::class ) ) {
        // Fallback: compact UA string when DeviceDetector isn't available yet.
        return isset( $_SERVER['HTTP_USER_AGENT'] ) ? md5( (string) $_SERVER['HTTP_USER_AGENT'] ) : 'unknown-device';
    }

    AbstractDeviceParser::setVersionTruncation( AbstractDeviceParser::VERSION_TRUNCATION_NONE );
    $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
    $dd = new DeviceDetector( $ua );
    $dd->parse();

    $parts = [
        $dd->getDeviceName() ?: 'unknown-device',
        $dd->getOs()['name'] ?? 'unknown-os',
        $dd->getBrandName() ?: 'unknown-brand',
        $dd->getModel() ?: 'unknown-model',
    ];

    return implode( '-', $parts );
}

/**
 * === Activation: Create Access Denied page ===
 */
function dl_activate_create_access_denied_page() {
    // Already have an ID saved?
    $saved_id = (int) get_option( dl_option_page_id_key() );
    if ( $saved_id && get_post( $saved_id ) ) {
        return;
    }

    // Existing page by path?
    $existing = get_page_by_path( 'access-denied', OBJECT, 'page' );
    if ( $existing instanceof WP_Post ) {
        update_option( dl_option_page_id_key(), (int) $existing->ID );
        return;
    }

    // Create page.
    $page_id = wp_insert_post(
        [
            'post_type'      => 'page',
            'post_name'      => 'access-denied',
            'post_title'     => __( 'Access Denied', 'device-limit-login' ),
            'post_status'    => 'publish',
            'post_content'   => __(
                '<p>Your account is now locked because you tried to login from another device or another browser. Our system only allows one device & one browser. Please contact our support team for assistance.</p>',
                'device-limit-login'
            ),
            'comment_status' => 'closed',
            'ping_status'    => 'closed',
        ]
    );

    if ( $page_id && ! is_wp_error( $page_id ) ) {
        update_option( dl_option_page_id_key(), (int) $page_id );
    }
}
register_activation_hook( __FILE__, 'dl_activate_create_access_denied_page' );

/**
 * === Enforce single-device limit on init ===
 */
function dl_check_device_limit() {
    if ( ! is_user_logged_in() || current_user_can( 'administrator' ) ) {
        return;
    }

    $user_id    = get_current_user_id();
    $device_id  = dl_get_device_id();

    $limit_meta = 'dl_device_limit';
    $slot1_meta = 'dl_device1';
    $block_meta = 'dl_blocked';

    // Initialize slot count to 1 if not set.
    if ( get_user_meta( $user_id, $limit_meta, true ) === '' ) {
        update_user_meta( $user_id, $limit_meta, 1 ); // one slot
    }

    $registered = get_user_meta( $user_id, $slot1_meta, true );
    $is_blocked = get_user_meta( $user_id, $block_meta, true );

    // Known device & not blocked => allow
    if ( ! $is_blocked && $registered === $device_id ) {
        return;
    }

    // First login from any device => register it and consume slot
    if ( empty( $registered ) ) {
        update_user_meta( $user_id, $slot1_meta, $device_id );
        update_user_meta( $user_id, $limit_meta, 0 );
        return;
    }

    // Otherwise => block and force logout, redirect to Access Denied permalink.
    update_user_meta( $user_id, $block_meta, 1 );

    $denied_url = dl_get_denied_url();

    add_action( 'wp_logout', function() use ( $denied_url ) {
        wp_safe_redirect( $denied_url );
        exit;
    } );

    wp_logout();
    wp_safe_redirect( $denied_url );
    exit;
}
add_action( 'init', 'dl_check_device_limit', 5 );

/**
 * === Force ALL URLs for blocked users to Access Denied page ===
 */
function dl_force_redirect_blocked_users() {
    if ( ! is_user_logged_in() ) {
        return;
    }
    if ( current_user_can( 'administrator' ) ) {
        return;
    }

    // Avoid interfering with admin screens, REST, or AJAX.
    if ( is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
        return;
    }

    $user_id    = get_current_user_id();
    $is_blocked = get_user_meta( $user_id, 'dl_blocked', true );
    if ( ! $is_blocked ) {
        return;
    }

    $page_id   = (int) get_option( dl_option_page_id_key() );
    $denied_url = dl_get_denied_url();

    // Prevent loop
    if ( $page_id && is_page( $page_id ) ) {
        return;
    }

    wp_safe_redirect( $denied_url, 302 );
    exit;
}
add_action( 'template_redirect', 'dl_force_redirect_blocked_users', 1 );

/**
 * === Users list: Restriction column ===
 */
function dl_manage_users_columns( $columns ) {
    $columns['dl_restriction'] = __( 'Restriction', 'device-limit-login' );
    return $columns;
}
add_filter( 'manage_users_columns', 'dl_manage_users_columns' );

function dl_manage_users_custom_column( $output, $column_name, $user_id ) {
    if ( 'dl_restriction' !== $column_name ) {
        return $output;
    }

    $user = get_userdata( $user_id );
    if ( $user && in_array( 'administrator', (array) $user->roles, true ) ) {
        return '';
    }

    $device1 = get_user_meta( $user_id, 'dl_device1', true );
    $blocked = get_user_meta( $user_id, 'dl_blocked', true );

    if ( $blocked ) {
        $url = wp_nonce_url(
            add_query_arg(
                [
                    'action'  => 'dl_revoke',
                    'user_id' => $user_id,
                ],
                admin_url( 'users.php' )
            ),
            'dl_revoke_' . $user_id
        );

        return sprintf(
            '<a href="%1$s" class="button button-small button-primary">%2$s</a><p>%3$s</p>',
            esc_url( $url ),
            esc_html__( 'Unblock', 'device-limit-login' ),
            esc_html( $device1 ? "Registered: $device1" : 'Registered: (none)' )
        );
    }

    if ( $device1 ) {
        return sprintf( '<p>%s</p>', esc_html( "Registered: $device1" ) );
    }

    return '';
}
add_filter( 'manage_users_custom_column', 'dl_manage_users_custom_column', 10, 3 );

/**
 * === Admin action: Unblock (resets device + slot) ===
 */
function dl_handle_revoke_action() {
    if ( ! is_admin() ) {
        return;
    }

    if ( empty( $_GET['action'] ) || $_GET['action'] !== 'dl_revoke' ) {
        return;
    }

    if ( ! current_user_can( 'administrator' ) ) {
        return;
    }

    $user_id = isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : 0;
    if ( ! $user_id ) {
        return;
    }

    check_admin_referer( 'dl_revoke_' . $user_id );

    delete_user_meta( $user_id, 'dl_blocked' );
    delete_user_meta( $user_id, 'dl_device1' );
    update_user_meta( $user_id, 'dl_device_limit', 1 );

    wp_safe_redirect( admin_url( 'users.php?dl_unblocked=1' ) );
    exit;
}
add_action( 'admin_init', 'dl_handle_revoke_action' );

/**
 * === (Optional) Noindex the Access Denied page ===
 */
function dl_noindex_access_denied() {
    $page_id = (int) get_option( dl_option_page_id_key() );
    if ( $page_id && is_page( $page_id ) ) {
        echo "<meta name='robots' content='noindex,nofollow' />\n";
    }
}
add_action( 'wp_head', 'dl_noindex_access_denied' );

/**
 * === Admin notice on successful unblock (optional) ===
 */
function dl_admin_unblocked_notice() {
    if ( isset( $_GET['dl_unblocked'] ) && '1' === $_GET['dl_unblocked'] ) {
        echo '<div class="notice notice-success is-dismissible"><p>' .
            esc_html__( 'User unblocked and device slot reset.', 'device-limit-login' ) .
            '</p></div>';
    }
}
add_action( 'admin_notices', 'dl_admin_unblocked_notice' );
