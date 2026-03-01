<?php
/**
 * PHPUnit bootstrap file for RivianTrackr AI Search Summary.
 *
 * Provides WordPress function stubs so the extracted classes can be tested
 * outside of a full WordPress environment.
 */

// Define ABSPATH so the class files will load.
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', '/tmp/wp/' );
}

// Plugin constants normally defined in the main plugin file.
if ( ! defined( 'RIVIANTRACKR_VERSION' ) ) {
	define( 'RIVIANTRACKR_VERSION', '1.3.0' );
}
if ( ! defined( 'RIVIANTRACKR_MAX_TOKENS' ) ) {
	define( 'RIVIANTRACKR_MAX_TOKENS', 1500 );
}
if ( ! defined( 'RIVIANTRACKR_API_TIMEOUT' ) ) {
	define( 'RIVIANTRACKR_API_TIMEOUT', 60 );
}
if ( ! defined( 'RIVIANTRACKR_IP_RATE_LIMIT' ) ) {
	define( 'RIVIANTRACKR_IP_RATE_LIMIT', 10 );
}
if ( ! defined( 'RIVIANTRACKR_IP_LOG_RATE_LIMIT' ) ) {
	define( 'RIVIANTRACKR_IP_LOG_RATE_LIMIT', 60 );
}
if ( ! defined( 'RIVIANTRACKR_RATE_LIMIT_WINDOW' ) ) {
	define( 'RIVIANTRACKR_RATE_LIMIT_WINDOW', 70 );
}
if ( ! defined( 'RIVIANTRACKR_ANTHROPIC_API_VERSION' ) ) {
	define( 'RIVIANTRACKR_ANTHROPIC_API_VERSION', '2023-06-01' );
}
if ( ! defined( 'RIVIANTRACKR_QUERY_MIN_LENGTH' ) ) {
	define( 'RIVIANTRACKR_QUERY_MIN_LENGTH', 2 );
}
if ( ! defined( 'RIVIANTRACKR_QUERY_MAX_LENGTH' ) ) {
	define( 'RIVIANTRACKR_QUERY_MAX_LENGTH', 500 );
}
if ( ! defined( 'RIVIANTRACKR_QUERY_MAX_BYTES' ) ) {
	define( 'RIVIANTRACKR_QUERY_MAX_BYTES', 2000 );
}
if ( ! defined( 'RIVIANTRACKR_ERROR_MAX_LENGTH' ) ) {
	define( 'RIVIANTRACKR_ERROR_MAX_LENGTH', 500 );
}
if ( ! defined( 'RIVIANTRACKR_CUSTOM_CSS_MAX_LENGTH' ) ) {
	define( 'RIVIANTRACKR_CUSTOM_CSS_MAX_LENGTH', 10000 );
}
if ( ! defined( 'RIVIANTRACKR_DEFAULT_CACHE_TTL' ) ) {
	define( 'RIVIANTRACKR_DEFAULT_CACHE_TTL', 3600 );
}

// Minimal WordPress function stubs for unit testing.
if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( $str ) {
		return trim( strip_tags( $str ) );
	}
}
if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $value ) {
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}
}
if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( $string ) {
		return strip_tags( $string );
	}
}
if ( ! function_exists( 'wp_salt' ) ) {
	function wp_salt( $scheme = 'auth' ) {
		return 'test-salt-' . $scheme;
	}
}
if ( ! function_exists( 'wp_json_encode' ) ) {
	function wp_json_encode( $data, $options = 0 ) {
		return json_encode( $data, $options );
	}
}
if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( $show ) {
		return 'Test Site';
	}
}

// In-memory option store for testing WordPress options API.
global $_wp_test_options;
$_wp_test_options = array();

if ( ! function_exists( 'get_option' ) ) {
	function get_option( $option, $default = false ) {
		global $_wp_test_options;
		return $_wp_test_options[ $option ] ?? $default;
	}
}
if ( ! function_exists( 'update_option' ) ) {
	function update_option( $option, $value, $autoload = null ) {
		global $_wp_test_options;
		$_wp_test_options[ $option ] = $value;
		return true;
	}
}
if ( ! function_exists( 'delete_option' ) ) {
	function delete_option( $option ) {
		global $_wp_test_options;
		unset( $_wp_test_options[ $option ] );
		return true;
	}
}

// In-memory transient store for testing.
global $_wp_test_transients;
$_wp_test_transients = array();

if ( ! function_exists( 'get_transient' ) ) {
	function get_transient( $transient ) {
		global $_wp_test_transients;
		return $_wp_test_transients[ $transient ] ?? false;
	}
}
if ( ! function_exists( 'set_transient' ) ) {
	function set_transient( $transient, $value, $expiration = 0 ) {
		global $_wp_test_transients;
		$_wp_test_transients[ $transient ] = $value;
		return true;
	}
}
if ( ! function_exists( 'delete_transient' ) ) {
	function delete_transient( $transient ) {
		global $_wp_test_transients;
		unset( $_wp_test_transients[ $transient ] );
		return true;
	}
}

// Load the autoloader.
require_once dirname( __DIR__ ) . '/includes/class-autoloader.php';
RivianTrackr\AISearchSummary\Autoloader::register( dirname( __DIR__ ) . '/includes' );
