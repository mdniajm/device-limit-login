<?php
/**
 * Plugin Name:     Device-Limit Login
 * Plugin URI:      https://github.com/mdniajm/device-limit-login/
 * Description:     Limits each non-admin user to two devices and blocks extra logins.
 * Version:         1.0.0
 * Author:          Md Niaj Makhdum
 * Author URI:      https://mdniajmakhdum.me
 * Text Domain:     device-limit-login
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Autoload the DeviceDetector library.
require_once __DIR__ . '/vendor/autoload.php';

use DeviceDetector\DeviceDetector;
use DeviceDetector\Parser\Device\AbstractDeviceParser;
/**
 * Build a unique device identifier from the user-agent.
 */
function dl_get_device_id() {
    AbstractDeviceParser::setVersionTruncation(AbstractDeviceParser::VERSION_TRUNCATION_NONE);
    $userAgent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $dd = new DeviceDetector( $userAgent );
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
 * Enforce the two-device limit on login.
 */
function dl_check_device_limit() {
    if ( ! is_user_logged_in() || current_user_can( 'administrator' ) ) {
        return;
    }

    $user_id    = get_current_user_id();
    $device_id  = dl_get_device_id();
    $limit_meta = 'dl_device_limit';
    $slot1_meta = 'dl_device1';
    $slot2_meta = 'dl_device2';
    $block_meta = 'dl_blocked';

    // Initialize limit if needed.
    if ( get_user_meta( $user_id, $limit_meta, true ) === '' ) {
        update_user_meta( $user_id, $limit_meta, 2 ); // two slots available
    }

    $remaining = (int) get_user_meta( $user_id, $limit_meta, true );

    // If device already registered, allow.
    $registered = [
        get_user_meta( $user_id, $slot1_meta, true ),
        get_user_meta( $user_id, $slot2_meta, true ),
    ];
    if ( in_array( $device_id, $registered, true ) && ! get_user_meta( $user_id, $block_meta, true ) ) {
        return;
    }

    // If we have free slots, register this device.
    if ( $remaining > 0 ) {
        if ( empty( $registered[0] ) ) {
            update_user_meta( $user_id, $slot1_meta, $device_id );
        } else {
            update_user_meta( $user_id, $slot2_meta, $device_id );
        }
        update_user_meta( $user_id, $limit_meta, $remaining - 1 );
        return;
    }

    // Otherwise, block and log out.
    update_user_meta( $user_id, $block_meta, 1 );
    add_action( 'wp_logout', function() {
        wp_safe_redirect( home_url( '/access-denied' ) );
        exit;
    } );
    wp_logout();
    wp_safe_redirect( home_url( '/access-denied' ) );
    exit;
}
add_action( 'init', 'dl_check_device_limit', 5 );

/**
 * Add a “Restriction” column to the Users table.
 */
function dl_manage_users_columns( $columns ) {
    $columns['dl_restriction'] = __( 'Restriction', 'device-limit-login' );
    return $columns;
}
add_filter( 'manage_users_columns', 'dl_manage_users_columns' );

/**
 * Populate our custom column.
 */
function dl_manage_users_custom_column( $value, $column_name, $user_id ) {
    if ( 'dl_restriction' !== $column_name ) {
        return $value;
    }
    $user      = get_userdata( $user_id );
    if ( in_array( 'administrator', (array) $user->roles, true ) ) {
        return '';
    }

    $device1 = get_user_meta( $user_id, 'dl_device1', true );
    $blocked = get_user_meta( $user_id, 'dl_blocked', true );

    $url = add_query_arg(
        [
            'action'  => 'dl_revoke',
            'user_id' => $user_id,
            'slot'    => 2,              // we only ever revoke slot2
        ],
        admin_url( 'users.php' )
    );

    if ( $blocked ) {
        return sprintf(
            '<a href="%1$s" class="button button-primary">%2$s</a><p>%3$s</p>',
            esc_url( $url ),
            esc_html__( 'Unblock', 'device-limit-login' ),
            esc_html( "1st Registered: $device1" )
        );
    }

    if ( $device1 ) {
        return sprintf(
            '<p>%s</p>',
            esc_html( "1st Registered: $device1" )
        );
    }

    return '';
}
add_filter( 'manage_users_custom_column', 'dl_manage_users_custom_column', 10, 3 );

/**
 * Handle the revoke action from the Users screen.
 */
function dl_handle_revoke_action() {
    if ( ! current_user_can( 'administrator' ) ) {
        return;
    }
    if ( empty( $_GET['action'] ) || $_GET['action'] !== 'dl_revoke' ) {
        return;
    }
    $user_id = intval( $_GET['user_id'] ?? 0 );
    $slot    = intval( $_GET['slot'] ?? 0 );

    if ( $user_id && $slot === 2 ) {
        // Remove block and slot2, give back one slot
        delete_user_meta( $user_id, 'dl_blocked' );
        delete_user_meta( $user_id, 'dl_device2' );

        $limit = (int) get_user_meta( $user_id, 'dl_device_limit', true );
        update_user_meta( $user_id, 'dl_device_limit', $limit + 1 );

        wp_safe_redirect( admin_url( 'users.php' ) );
        exit;
    }
}
add_action( 'admin_init', 'dl_handle_revoke_action' );

