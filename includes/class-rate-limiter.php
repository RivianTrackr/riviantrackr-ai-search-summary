<?php
declare(strict_types=1);

namespace RivianTrackr\AISearchSummary;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles IP-based rate limiting, global AI call rate limiting, and bot detection.
 */
class RateLimiter {

	/**
	 * Check if an IP is rate limited for summary requests.
	 *
	 * Uses a single transient per IP with timestamp tracking.
	 *
	 * @param string $ip Client IP address.
	 * @return bool True if rate limited.
	 */
	public function is_ip_rate_limited( string $ip ): bool {
		$ip_hash  = hash( 'sha256', $ip );
		$key      = 'riviantrackr_ip_rate_' . substr( $ip_hash, 0, 32 );
		$lock_key = $key . '_lock';
		$limit    = RIVIANTRACKR_IP_RATE_LIMIT;
		$now      = time();
		$cutoff   = $now - 60;

		// Acquire a short-lived lock to prevent race conditions.
		$lock_attempts = 0;
		while ( get_transient( $lock_key ) && $lock_attempts < 5 ) {
			usleep( 50000 ); // 50 ms
			$lock_attempts++;
		}
		set_transient( $lock_key, 1, 5 );

		$timestamps = get_transient( $key );
		if ( ! is_array( $timestamps ) ) {
			$timestamps = array();
		}

		$timestamps = array_values( array_filter( $timestamps, function ( $ts ) use ( $cutoff ) {
			return $ts > $cutoff;
		} ) );

		if ( count( $timestamps ) >= $limit ) {
			delete_transient( $lock_key );
			return true;
		}

		$timestamps[] = $now;
		set_transient( $key, $timestamps, RIVIANTRACKR_RATE_LIMIT_WINDOW );
		delete_transient( $lock_key );

		return false;
	}

	/**
	 * Get rate limit info for an IP.
	 *
	 * @param string $ip Client IP address.
	 * @return array{limit: int, remaining: int, used: int, reset: int}
	 */
	public function get_rate_limit_info( string $ip ): array {
		$limit   = RIVIANTRACKR_IP_RATE_LIMIT;
		$ip_hash = hash( 'sha256', $ip );
		$key     = 'riviantrackr_ip_rate_' . substr( $ip_hash, 0, 32 );

		$timestamps = get_transient( $key );
		if ( ! is_array( $timestamps ) ) {
			$timestamps = array();
		}

		$now    = time();
		$cutoff = $now - 60;
		$recent = array_filter( $timestamps, function ( $ts ) use ( $cutoff ) {
			return $ts > $cutoff;
		} );

		$used  = count( $recent );
		$reset = $now + 60;
		if ( ! empty( $recent ) ) {
			$oldest = min( $recent );
			$reset  = $oldest + 60;
		}

		return array(
			'limit'     => $limit,
			'remaining' => max( 0, $limit - $used ),
			'used'      => $used,
			'reset'     => $reset,
		);
	}

	/**
	 * Lightweight rate limiter for logging and feedback endpoints.
	 *
	 * @param string $ip Client IP address.
	 * @return bool True if the IP has exceeded the log rate limit.
	 */
	public function is_log_rate_limited( string $ip ): bool {
		$ip_hash = hash( 'sha256', $ip );
		$key     = 'riviantrackr_log_rate_' . substr( $ip_hash, 0, 32 );
		$limit   = RIVIANTRACKR_IP_LOG_RATE_LIMIT;
		$now     = time();
		$cutoff  = $now - 60;

		$timestamps = get_transient( $key );
		if ( ! is_array( $timestamps ) ) {
			$timestamps = array();
		}

		$timestamps = array_values( array_filter( $timestamps, function ( $ts ) use ( $cutoff ) {
			return $ts > $cutoff;
		} ) );

		if ( count( $timestamps ) >= $limit ) {
			return true;
		}

		$timestamps[] = $now;
		set_transient( $key, $timestamps, RIVIANTRACKR_RATE_LIMIT_WINDOW );

		return false;
	}

	/**
	 * Check if global AI call rate limit has been reached.
	 *
	 * @param int $limit Max calls per minute (0 = unlimited).
	 * @return bool True if rate limited.
	 */
	public function is_ai_call_rate_limited( int $limit ): bool {
		if ( $limit <= 0 ) {
			return false;
		}

		$key   = 'riviantrackr_rate_' . gmdate( 'YmdHi' );
		$count = (int) get_transient( $key );

		if ( $count >= $limit ) {
			return true;
		}

		$count++;
		set_transient( $key, $count, RIVIANTRACKR_RATE_LIMIT_WINDOW );

		return false;
	}

	/**
	 * Detect if the current request is likely from a bot.
	 *
	 * @return bool True if likely a bot.
	 */
	public function is_likely_bot(): bool {
		if ( ! isset( $_SERVER['HTTP_USER_AGENT'] ) || empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
			return true;
		}

		$user_agent = strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) );

		if ( strlen( $user_agent ) < 20 ) {
			return true;
		}

		$bot_patterns = array(
			'bot', 'crawl', 'spider', 'slurp', 'scanner',
			'scraper', 'curl', 'wget', 'python', 'java/',
			'libwww', 'httpunit', 'nutch', 'phpcrawl',
			'msnbot', 'adidxbot', 'blekkobot', 'teoma',
			'gigabot', 'dotbot', 'yandex', 'seokicks',
			'ahrefsbot', 'semrushbot', 'mj12bot', 'baiduspider',
			'headless', 'phantom', 'selenium', 'puppeteer',
			'playwright', 'webdriver', 'httpclient', 'okhttp',
			'go-http-client', 'apache-httpclient', 'node-fetch',
			'axios', 'request/', 'postman', 'insomnia',
		);

		foreach ( $bot_patterns as $pattern ) {
			if ( strpos( $user_agent, $pattern ) !== false ) {
				return true;
			}
		}

		if ( empty( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ) {
			return true;
		}

		if ( empty( $_SERVER['HTTP_ACCEPT'] ) ) {
			return true;
		}

		if ( strpos( $user_agent, 'headlesschrome' ) !== false ) {
			return true;
		}

		$claims_browser = (
			strpos( $user_agent, 'mozilla' ) !== false ||
			strpos( $user_agent, 'chrome' ) !== false ||
			strpos( $user_agent, 'safari' ) !== false ||
			strpos( $user_agent, 'firefox' ) !== false ||
			strpos( $user_agent, 'edge' ) !== false
		);

		if ( $claims_browser && empty( $_SERVER['HTTP_ACCEPT_ENCODING'] ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Validate the bot challenge token sent from the frontend.
	 *
	 * @param string|null $token     The bot challenge token.
	 * @param int|null    $timestamp The token timestamp.
	 * @return bool True if valid (or no token provided).
	 */
	public function validate_bot_token( ?string $token, ?int $timestamp ): bool {
		if ( ! $token || ! $timestamp ) {
			return true; // No token to validate
		}

		$expected = hash_hmac( 'sha256', (string) $timestamp, wp_salt( 'nonce' ) );
		$age      = time() - $timestamp;

		return hash_equals( $expected, $token ) && $age >= 0 && $age <= 600;
	}

	/**
	 * Record a rate-limit strike against an IP for progressive penalties.
	 *
	 * Strike escalation:
	 *   1st strike: no extra ban (normal 60s window applies)
	 *   2nd strike within 10 min: 5-minute ban
	 *   3rd strike within 30 min: 30-minute ban
	 *   4th+ strike within 1 hour: 24-hour ban
	 *
	 * @param string $ip Client IP address.
	 */
	public function record_strike( string $ip ): void {
		$ip_hash    = hash( 'sha256', $ip );
		$key        = 'riviantrackr_strikes_' . substr( $ip_hash, 0, 32 );
		$ban_key    = 'riviantrackr_ban_' . substr( $ip_hash, 0, 32 );
		$now        = time();

		$strikes = get_transient( $key );
		if ( ! is_array( $strikes ) ) {
			$strikes = array();
		}

		// Keep only strikes from the last hour.
		$cutoff  = $now - 3600;
		$strikes = array_values( array_filter( $strikes, function ( $ts ) use ( $cutoff ) {
			return $ts > $cutoff;
		} ) );

		$strikes[] = $now;
		set_transient( $key, $strikes, 86400 );

		$count = count( $strikes );

		// Determine ban duration based on strike count.
		$ban_duration = 0;
		if ( $count >= 4 ) {
			$ban_duration = 86400; // 24 hours
		} elseif ( $count >= 3 ) {
			// Only if 3rd strike within 30 min of 1st.
			$window_strikes = array_filter( $strikes, function ( $ts ) use ( $now ) {
				return $ts > ( $now - 1800 );
			} );
			if ( count( $window_strikes ) >= 3 ) {
				$ban_duration = 1800; // 30 minutes
			}
		} elseif ( $count >= 2 ) {
			// Only if 2nd strike within 10 min of 1st.
			$window_strikes = array_filter( $strikes, function ( $ts ) use ( $now ) {
				return $ts > ( $now - 600 );
			} );
			if ( count( $window_strikes ) >= 2 ) {
				$ban_duration = 300; // 5 minutes
			}
		}

		if ( $ban_duration > 0 ) {
			set_transient( $ban_key, $now + $ban_duration, $ban_duration );
		}
	}

	/**
	 * Check if an IP is currently banned from progressive penalties.
	 *
	 * @param string $ip Client IP address.
	 * @return bool True if banned.
	 */
	public function is_ip_banned( string $ip ): bool {
		$ip_hash = hash( 'sha256', $ip );
		$ban_key = 'riviantrackr_ban_' . substr( $ip_hash, 0, 32 );

		$expiry = get_transient( $ban_key );
		if ( false === $expiry ) {
			return false;
		}

		return time() < (int) $expiry;
	}

	/**
	 * Get the remaining seconds of an IP ban.
	 *
	 * @param string $ip Client IP address.
	 * @return int Remaining seconds, or 0 if not banned.
	 */
	public function get_ban_expiry( string $ip ): int {
		$ip_hash = hash( 'sha256', $ip );
		$ban_key = 'riviantrackr_ban_' . substr( $ip_hash, 0, 32 );

		$expiry = get_transient( $ban_key );
		if ( false === $expiry ) {
			return 0;
		}

		return max( 0, (int) $expiry - time() );
	}

	/**
	 * Check if the same query from the same IP was made recently.
	 *
	 * Blocks duplicate queries from the same IP within a 5-minute window
	 * to prevent bots from hammering the same search repeatedly.
	 *
	 * @param string $ip    Client IP address.
	 * @param string $query Search query string.
	 * @return bool True if this is a duplicate (should be throttled).
	 */
	public function is_duplicate_query( string $ip, string $query ): bool {
		$ip_hash    = substr( hash( 'sha256', $ip ), 0, 16 );
		$query_hash = substr( hash( 'sha256', strtolower( trim( $query ) ) ), 0, 16 );
		$key        = 'riviantrackr_dup_' . $ip_hash . '_' . $query_hash;

		$existing = get_transient( $key );
		if ( false !== $existing ) {
			return true;
		}

		set_transient( $key, 1, 300 ); // 5-minute window
		return false;
	}

	/**
	 * Get the client IP address.
	 *
	 * @return string Client IP or 'unknown'.
	 */
	public function get_client_ip(): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';

		if ( defined( 'RIVIANTRACKR_TRUSTED_PROXY_HEADER' ) && RIVIANTRACKR_TRUSTED_PROXY_HEADER ) {
			$header = 'HTTP_' . strtoupper( str_replace( '-', '_', RIVIANTRACKR_TRUSTED_PROXY_HEADER ) );
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) );
				$forwarded_ip = trim( $ips[0] );
				if ( filter_var( $forwarded_ip, FILTER_VALIDATE_IP ) ) {
					$ip = $forwarded_ip;
				}
			}
		}

		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $ip;
		}

		return 'unknown';
	}
}
