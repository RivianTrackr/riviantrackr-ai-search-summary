<?php
declare(strict_types=1);

namespace RivianTrackr\AISearchSummary;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * PSR-4-style autoloader for the RivianTrackr\AISearchSummary namespace.
 *
 * Maps class names to file paths within the includes/ directory.
 * Example: RivianTrackr\AISearchSummary\CacheManager → includes/class-cache-manager.php
 */
class Autoloader {

	/**
	 * Base directory for the namespace.
	 *
	 * @var string
	 */
	private static string $base_dir = '';

	/**
	 * Register the autoloader.
	 *
	 * @param string $base_dir Path to the includes/ directory.
	 */
	public static function register( string $base_dir ): void {
		self::$base_dir = rtrim( $base_dir, '/' ) . '/';
		spl_autoload_register( array( self::class, 'autoload' ) );
	}

	/**
	 * Autoload callback.
	 *
	 * @param string $class Fully-qualified class name.
	 */
	public static function autoload( string $class ): void {
		$prefix = 'RivianTrackr\\AISearchSummary\\';

		if ( strpos( $class, $prefix ) !== 0 ) {
			return;
		}

		$relative_class = substr( $class, strlen( $prefix ) );

		// Convert CamelCase to kebab-case: CacheManager → cache-manager
		$file_name = strtolower( preg_replace( '/([a-z])([A-Z])/', '$1-$2', $relative_class ) );
		$file_name = str_replace( '\\', '/', $file_name );

		$file = self::$base_dir . 'class-' . $file_name . '.php';

		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
}
