<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Tests for the Autoloader.
 *
 * Verifies that the autoloader can resolve all namespaced classes.
 */
class AutoloaderTest extends TestCase {

	public function test_api_handler_class_exists(): void {
		$this->assertTrue( class_exists( \RivianTrackr\AISearchSummary\ApiHandler::class ) );
	}

	public function test_cache_manager_class_exists(): void {
		$this->assertTrue( class_exists( \RivianTrackr\AISearchSummary\CacheManager::class ) );
	}

	public function test_rate_limiter_class_exists(): void {
		$this->assertTrue( class_exists( \RivianTrackr\AISearchSummary\RateLimiter::class ) );
	}

	public function test_analytics_class_exists(): void {
		$this->assertTrue( class_exists( \RivianTrackr\AISearchSummary\Analytics::class ) );
	}

	public function test_input_validator_class_exists(): void {
		$this->assertTrue( class_exists( \RivianTrackr\AISearchSummary\InputValidator::class ) );
	}

	public function test_autoloader_class_exists(): void {
		$this->assertTrue( class_exists( \RivianTrackr\AISearchSummary\Autoloader::class ) );
	}

	public function test_nonexistent_class_does_not_error(): void {
		// The autoloader should silently fail for unknown classes.
		$this->assertFalse( class_exists( \RivianTrackr\AISearchSummary\DoesNotExist::class ) );
	}
}
