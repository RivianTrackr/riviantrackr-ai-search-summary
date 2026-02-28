<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use RivianTrackr\AISearchSummary\CacheManager;

/**
 * Tests for the CacheManager class.
 *
 * Covers cache key generation and determinism.
 * Note: get/set/clear tests require WordPress transient functions,
 * so only key building logic is fully tested here.
 */
class CacheManagerTest extends TestCase {

	private CacheManager $cache;

	protected function setUp(): void {
		$this->cache = new CacheManager();
	}

	// --- Cache Key Building ---

	public function test_build_key_returns_string(): void {
		$key = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'rivian r1t' );
		$this->assertIsString( $key );
		$this->assertNotEmpty( $key );
	}

	public function test_build_key_is_deterministic(): void {
		$key1 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'rivian r1t' );
		$key2 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'rivian r1t' );
		$this->assertSame( $key1, $key2 );
	}

	public function test_different_queries_produce_different_keys(): void {
		$key1 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'rivian r1t' );
		$key2 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'rivian r1s' );
		$this->assertNotSame( $key1, $key2 );
	}

	public function test_different_providers_produce_different_keys(): void {
		$key1 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'test query' );
		$key2 = $this->cache->build_key( 'anthropic', 'gpt-4o', 10, 400, 'test query' );
		$this->assertNotSame( $key1, $key2 );
	}

	public function test_different_models_produce_different_keys(): void {
		$key1 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'test query' );
		$key2 = $this->cache->build_key( 'openai', 'gpt-4o-mini', 10, 400, 'test query' );
		$this->assertNotSame( $key1, $key2 );
	}

	public function test_different_content_length_produces_different_keys(): void {
		$key1 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'test query' );
		$key2 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 800, 'test query' );
		$this->assertNotSame( $key1, $key2 );
	}

	public function test_different_max_posts_produces_different_keys(): void {
		$key1 = $this->cache->build_key( 'openai', 'gpt-4o', 5, 400, 'test query' );
		$key2 = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'test query' );
		$this->assertNotSame( $key1, $key2 );
	}

	public function test_key_contains_version_prefix(): void {
		$key = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'test' );
		$this->assertStringContainsString( 'riviantrackr_v', $key );
	}

	public function test_key_contains_namespace(): void {
		$key = $this->cache->build_key( 'openai', 'gpt-4o', 10, 400, 'test' );
		$this->assertStringContainsString( 'ns', $key );
	}
}
