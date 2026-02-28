<?php
declare(strict_types=1);

namespace RivianTrackr\AISearchSummary;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manages server-side transient caching and namespace-based invalidation.
 */
class CacheManager {

	private string $cache_keys_option      = 'riviantrackr_cache_keys';
	private string $cache_namespace_option = 'riviantrackr_cache_namespace';
	private string $models_cache_option    = 'riviantrackr_models_cache';
	private string $cache_prefix;
	private int    $default_ttl = 3600;

	public function __construct() {
		$this->cache_prefix = 'riviantrackr_v' . str_replace( '.', '_', RIVIANTRACKR_VERSION ) . '_';
	}

	/**
	 * Get the current cache namespace version.
	 */
	public function get_namespace(): int {
		$ns = (int) get_option( $this->cache_namespace_option, 1 );
		if ( $ns < 1 ) {
			$ns = 1;
			update_option( $this->cache_namespace_option, $ns );
		}
		return $ns;
	}

	/**
	 * Bump the cache namespace, invalidating all previous cached entries.
	 */
	public function bump_namespace(): int {
		$ns = $this->get_namespace();
		$ns++;
		update_option( $this->cache_namespace_option, $ns );
		return $ns;
	}

	/**
	 * Clear all AI summary caches.
	 */
	public function clear(): bool {
		$this->bump_namespace();

		// Backward compatibility cleanup: older versions stored explicit transient keys.
		$keys = get_option( $this->cache_keys_option, array() );
		if ( is_array( $keys ) ) {
			foreach ( $keys as $key ) {
				delete_transient( $key );
			}
		}
		delete_option( $this->cache_keys_option );

		return true;
	}

	/**
	 * Generate a cache key for a search query.
	 *
	 * @param string $provider   AI provider name.
	 * @param string $model      Model ID.
	 * @param int    $max_posts  Max posts setting.
	 * @param int    $content_length Content length setting.
	 * @param string $query      Normalized search query.
	 * @return string Cache key.
	 */
	public function build_key( string $provider, string $model, int $max_posts, int $content_length, string $query ): string {
		$namespace = $this->get_namespace();
		$data      = implode( '|', array( $provider, $model, $max_posts, $content_length, $query ) );
		return $this->cache_prefix . 'ns' . $namespace . '_' . hash( 'sha256', $data );
	}

	/**
	 * Retrieve cached data for a key.
	 *
	 * @param string $key Cache key.
	 * @return array|null Decoded data or null on miss/corrupt.
	 */
	public function get( string $key ): ?array {
		$raw = get_transient( $key );
		if ( ! $raw ) {
			return null;
		}

		$data = json_decode( $raw, true );
		if ( json_last_error() !== JSON_ERROR_NONE || ! is_array( $data ) ) {
			delete_transient( $key );
			return null;
		}

		return $data;
	}

	/**
	 * Store data in cache.
	 *
	 * @param string $key  Cache key.
	 * @param array  $data Data to cache.
	 * @param int    $ttl  TTL in seconds (0 = use default).
	 */
	public function set( string $key, array $data, int $ttl = 0 ): void {
		if ( $ttl <= 0 ) {
			$ttl = $this->default_ttl;
		}
		set_transient( $key, wp_json_encode( $data ), $ttl );
	}

	/**
	 * Get cached OpenAI models list.
	 *
	 * @return array{models: string[], updated_at: int}|null
	 */
	public function get_models_cache(): ?array {
		$cache = get_option( $this->models_cache_option );
		if ( is_array( $cache ) && ! empty( $cache['models'] ) && ! empty( $cache['updated_at'] ) ) {
			return $cache;
		}
		return null;
	}

	/**
	 * Store the OpenAI models list cache.
	 *
	 * @param string[] $models Model IDs.
	 */
	public function set_models_cache( array $models ): void {
		update_option(
			$this->models_cache_option,
			array(
				'models'     => $models,
				'updated_at' => time(),
			)
		);
	}
}
