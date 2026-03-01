<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use RivianTrackr\AISearchSummary\RateLimiter;

/**
 * Tests for the RateLimiter class.
 *
 * Covers progressive IP penalties (strike system), duplicate query throttling,
 * bot token validation, and IP-based rate limiting.
 */
class RateLimiterTest extends TestCase {

	private RateLimiter $limiter;

	protected function setUp(): void {
		// Clear all transients before each test.
		global $_wp_test_transients;
		$_wp_test_transients = array();

		$this->limiter = new RateLimiter();
	}

	// --- Progressive IP Penalties ---

	public function test_no_ban_initially(): void {
		$this->assertFalse( $this->limiter->is_ip_banned( '192.168.1.1' ) );
	}

	public function test_no_ban_after_single_strike(): void {
		$this->limiter->record_strike( '192.168.1.1' );
		$this->assertFalse( $this->limiter->is_ip_banned( '192.168.1.1' ) );
	}

	public function test_ban_after_two_strikes_within_10_min(): void {
		$this->limiter->record_strike( '192.168.1.1' );
		$this->limiter->record_strike( '192.168.1.1' );
		$this->assertTrue( $this->limiter->is_ip_banned( '192.168.1.1' ) );
	}

	public function test_ban_expiry_positive_after_strikes(): void {
		$this->limiter->record_strike( '192.168.1.1' );
		$this->limiter->record_strike( '192.168.1.1' );
		$expiry = $this->limiter->get_ban_expiry( '192.168.1.1' );
		$this->assertGreaterThan( 0, $expiry );
		$this->assertLessThanOrEqual( 300, $expiry ); // 5-minute ban
	}

	public function test_ban_escalates_with_three_strikes(): void {
		$this->limiter->record_strike( '192.168.1.1' );
		$this->limiter->record_strike( '192.168.1.1' );
		$this->limiter->record_strike( '192.168.1.1' );
		$expiry = $this->limiter->get_ban_expiry( '192.168.1.1' );
		// Should be 30-minute ban (1800s), not 5-minute
		$this->assertGreaterThan( 300, $expiry );
		$this->assertLessThanOrEqual( 1800, $expiry );
	}

	public function test_ban_escalates_with_four_strikes(): void {
		$this->limiter->record_strike( '192.168.1.1' );
		$this->limiter->record_strike( '192.168.1.1' );
		$this->limiter->record_strike( '192.168.1.1' );
		$this->limiter->record_strike( '192.168.1.1' );
		$expiry = $this->limiter->get_ban_expiry( '192.168.1.1' );
		// Should be 24-hour ban (86400s)
		$this->assertGreaterThan( 1800, $expiry );
		$this->assertLessThanOrEqual( 86400, $expiry );
	}

	public function test_ban_expiry_zero_when_not_banned(): void {
		$this->assertSame( 0, $this->limiter->get_ban_expiry( '192.168.1.1' ) );
	}

	public function test_different_ips_tracked_independently(): void {
		$this->limiter->record_strike( '192.168.1.1' );
		$this->limiter->record_strike( '192.168.1.1' );
		$this->assertTrue( $this->limiter->is_ip_banned( '192.168.1.1' ) );
		$this->assertFalse( $this->limiter->is_ip_banned( '10.0.0.1' ) );
	}

	// --- Duplicate Query Throttling ---

	public function test_first_query_not_duplicate(): void {
		$this->assertFalse( $this->limiter->is_duplicate_query( '192.168.1.1', 'rivian r1t review' ) );
	}

	public function test_same_query_same_ip_is_duplicate(): void {
		$this->limiter->is_duplicate_query( '192.168.1.1', 'rivian r1t review' );
		$this->assertTrue( $this->limiter->is_duplicate_query( '192.168.1.1', 'rivian r1t review' ) );
	}

	public function test_different_query_same_ip_not_duplicate(): void {
		$this->limiter->is_duplicate_query( '192.168.1.1', 'rivian r1t review' );
		$this->assertFalse( $this->limiter->is_duplicate_query( '192.168.1.1', 'rivian r1s price' ) );
	}

	public function test_same_query_different_ip_not_duplicate(): void {
		$this->limiter->is_duplicate_query( '192.168.1.1', 'rivian r1t review' );
		$this->assertFalse( $this->limiter->is_duplicate_query( '10.0.0.1', 'rivian r1t review' ) );
	}

	public function test_duplicate_query_case_insensitive(): void {
		$this->limiter->is_duplicate_query( '192.168.1.1', 'Rivian R1T Review' );
		$this->assertTrue( $this->limiter->is_duplicate_query( '192.168.1.1', 'rivian r1t review' ) );
	}

	// --- Bot Token Validation ---

	public function test_validate_bot_token_returns_true_when_no_token(): void {
		$this->assertTrue( $this->limiter->validate_bot_token( null, null ) );
	}

	public function test_validate_bot_token_rejects_invalid_token(): void {
		$this->assertFalse( $this->limiter->validate_bot_token( 'invalid-token', time() ) );
	}

	public function test_validate_bot_token_accepts_valid_token(): void {
		$ts    = time();
		$token = hash_hmac( 'sha256', (string) $ts, wp_salt( 'nonce' ) );
		$this->assertTrue( $this->limiter->validate_bot_token( $token, $ts ) );
	}

	public function test_validate_bot_token_rejects_expired_token(): void {
		$ts    = time() - 700; // Older than 600s window
		$token = hash_hmac( 'sha256', (string) $ts, wp_salt( 'nonce' ) );
		$this->assertFalse( $this->limiter->validate_bot_token( $token, $ts ) );
	}

	// --- IP Rate Limiting ---

	public function test_first_request_not_rate_limited(): void {
		$this->assertFalse( $this->limiter->is_ip_rate_limited( '192.168.1.1' ) );
	}

	public function test_rate_limited_after_exceeding_limit(): void {
		for ( $i = 0; $i < RIVIANTRACKR_IP_RATE_LIMIT; $i++ ) {
			$this->limiter->is_ip_rate_limited( '192.168.1.1' );
		}
		$this->assertTrue( $this->limiter->is_ip_rate_limited( '192.168.1.1' ) );
	}

	public function test_rate_limit_info_shows_remaining(): void {
		$this->limiter->is_ip_rate_limited( '192.168.1.1' );
		$info = $this->limiter->get_rate_limit_info( '192.168.1.1' );
		$this->assertSame( RIVIANTRACKR_IP_RATE_LIMIT, $info['limit'] );
		$this->assertSame( 1, $info['used'] );
		$this->assertSame( RIVIANTRACKR_IP_RATE_LIMIT - 1, $info['remaining'] );
	}

	// --- Log Rate Limiting ---

	public function test_log_first_request_not_rate_limited(): void {
		$this->assertFalse( $this->limiter->is_log_rate_limited( '192.168.1.1' ) );
	}

	// --- Client IP ---

	public function test_get_client_ip_returns_unknown_when_missing(): void {
		unset( $_SERVER['REMOTE_ADDR'] );
		$this->assertSame( 'unknown', $this->limiter->get_client_ip() );
	}

	public function test_get_client_ip_returns_valid_ip(): void {
		$_SERVER['REMOTE_ADDR'] = '192.168.1.100';
		$this->assertSame( '192.168.1.100', $this->limiter->get_client_ip() );
	}
}
