<?php
declare(strict_types=1);

namespace RivianTrackr\AISearchSummary;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Validates and sanitizes user inputs: search queries, SQL injection detection,
 * spam filtering, and custom CSS sanitization.
 */
class InputValidator {

	/**
	 * Validate a search query string.
	 *
	 * @param string $value     Query value.
	 * @param array  $options   Plugin options (for blocklist).
	 * @return bool True if valid.
	 */
	public function validate_search_query( string $value, array $options = array() ): bool {
		if ( empty( trim( $value ) ) ) {
			return false;
		}

		$length = function_exists( 'mb_strlen' ) ? mb_strlen( $value, 'UTF-8' ) : strlen( $value );
		if ( $length < RIVIANTRACKR_QUERY_MIN_LENGTH || $length > RIVIANTRACKR_QUERY_MAX_LENGTH ) {
			return false;
		}

		if ( strlen( $value ) > RIVIANTRACKR_QUERY_MAX_BYTES ) {
			return false;
		}

		if ( $this->is_sql_injection_attempt( $value ) ) {
			return false;
		}

		if ( $this->is_spam_query( $value, $options ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Detect SQL injection patterns in input.
	 *
	 * @param string $value Input value to check.
	 * @return bool True if SQL injection pattern detected.
	 */
	public function is_sql_injection_attempt( string $value ): bool {
		$normalized = strtolower( urldecode( $value ) );
		$normalized = preg_replace( '/\/\*.*?\*\//', ' ', $normalized );
		$normalized = preg_replace( '/[\s\x00-\x1f]+/', ' ', $normalized );

		$sql_patterns = array(
			'select.*from',
			'union.*select',
			'insert.*into',
			'delete.*from',
			'update.*set',
			'drop.*table',
			'create.*table',
			'alter.*table',
			'exec.*\(',
			'execute.*\(',
			'concat\s*\(',
			'char\s*\(',
			'chr\s*\(',
			'substring\s*\(',
			'ascii\s*\(',
			'hex\s*\(',
			'unhex\s*\(',
			'load_file\s*\(',
			'outfile',
			'dumpfile',
			'benchmark\s*\(',
			'sleep\s*\(',
			'waitfor.*delay',
			'ctxsys\.',
			'drithsx',
			'from\s+dual',
			'dbms_',
			'utl_',
			'xp_cmdshell',
			'sp_executesql',
			'information_schema',
			'sysobjects',
			'syscolumns',
			'\band\b.*=.*\bcase\b',
			'\bor\b.*=.*\bcase\b',
			'when.*then.*else.*end',
			'--\s*$',
			'#\s*$',
			';\s*select',
			';\s*insert',
			';\s*update',
			';\s*delete',
			';\s*drop',
		);

		foreach ( $sql_patterns as $pattern ) {
			if ( preg_match( '/' . $pattern . '/i', $normalized ) ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
					error_log( '[RivianTrackr AI Search Summary] Blocked SQL injection attempt: ' . substr( $value, 0, 100 ) );
				}
				return true;
			}
		}

		$special_char_count = preg_match_all( '/[\'"\(\)\|\=\;\%]/', $value );
		if ( $special_char_count > 10 ) {
			return true;
		}

		return false;
	}

	/**
	 * Detect spam patterns in search queries.
	 *
	 * @param string $value   Input value to check.
	 * @param array  $options Plugin options (for blocklist).
	 * @return bool True if spam pattern detected.
	 */
	public function is_spam_query( string $value, array $options = array() ): bool {
		$normalized = strtolower( trim( $value ) );

		// URLs
		if ( preg_match( '#https?://|www\.#i', $normalized ) ) {
			return true;
		}

		// Email addresses
		if ( preg_match( '/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i', $normalized ) ) {
			return true;
		}

		// Phone numbers (7+ consecutive digits)
		$digits_only = preg_replace( '/[\s\-\.\(\)]+/', '', $normalized );
		if ( preg_match( '/\d{7,}/', $digits_only ) ) {
			return true;
		}

		// Excessive character repetition
		if ( preg_match( '/(.)\1{5,}/', $normalized ) ) {
			return true;
		}
		if ( preg_match( '/\b(\w+)\b(?:\s+\1\b){3,}/i', $normalized ) ) {
			return true;
		}

		// Common spam keywords
		$spam_patterns = array(
			'buy cheap', 'order now', 'free shipping', 'click here', 'act now',
			'limited time offer', 'viagra', 'cialis', 'casino', 'poker online',
			'slot machine', 'payday loan', 'earn money fast', 'work from home',
			'make money online', 'weight loss', 'diet pill', 'enlargement',
			'nigerian prince', 'cryptocurrency investment', 'binary option',
			'forex trading', 'seo service', 'backlink', 'guest post service',
			'telegram', 'whatsapp.*group', 'join.*channel',
		);

		foreach ( $spam_patterns as $pattern ) {
			if ( preg_match( '/' . $pattern . '/i', $normalized ) ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
					error_log( '[RivianTrackr AI Search Summary] Blocked spam query (pattern: ' . $pattern . '): ' . substr( $value, 0, 100 ) );
				}
				return true;
			}
		}

		// Scanner probes
		$scanner_probes = array(
			'QUERY_STRING', 'DOCUMENT_ROOT', 'SERVER_NAME', 'SERVER_ADDR',
			'REMOTE_ADDR', 'REMOTE_HOST', 'HTTP_HOST', 'HTTP_USER_AGENT',
			'HTTP_REFERER', 'HTTP_ACCEPT', 'PATH_INFO', 'SCRIPT_FILENAME',
			'SCRIPT_NAME', 'PHP_SELF', 'REQUEST_URI', 'REQUEST_METHOD',
			'CONTENT_TYPE', 'CONTENT_LENGTH', 'SERVER_SOFTWARE', 'SERVER_PROTOCOL',
			'GATEWAY_INTERFACE', 'SERVER_PORT', 'PATH_TRANSLATED', 'AUTH_TYPE',
		);
		foreach ( $scanner_probes as $probe ) {
			if ( stripos( $normalized, strtolower( $probe ) ) !== false ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
					error_log( '[RivianTrackr AI Search Summary] Blocked scanner probe query (variable: ' . $probe . '): ' . substr( $value, 0, 100 ) );
				}
				return true;
			}
		}

		// High ratio of non-alphanumeric characters
		$alpha_count = preg_match_all( '/[a-z0-9]/i', $value );
		$total_len   = max( 1, strlen( $value ) );
		if ( $total_len > 10 && ( $alpha_count / $total_len ) < 0.5 ) {
			return true;
		}

		// Admin-configurable blocklist
		$blocklist = isset( $options['spam_blocklist'] ) ? $options['spam_blocklist'] : '';
		if ( ! empty( $blocklist ) ) {
			$blocked_terms = array_filter( array_map( 'trim', explode( "\n", strtolower( $blocklist ) ) ) );
			foreach ( $blocked_terms as $term ) {
				if ( empty( $term ) ) {
					continue;
				}
				if ( strpos( $normalized, $term ) !== false ) {
					if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
						// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
						error_log( '[RivianTrackr AI Search Summary] Blocked query via blocklist (term: ' . $term . '): ' . substr( $value, 0, 100 ) );
					}
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Sanitize custom CSS input.
	 *
	 * Removes dangerous patterns (JS URLs, expressions, data URIs with
	 * non-image MIME types) while preserving valid CSS.
	 *
	 * @param string $css Raw CSS input.
	 * @return string Sanitized CSS.
	 */
	public function sanitize_custom_css( string $css ): string {
		if ( empty( $css ) ) {
			return '';
		}

		// Strip null bytes
		$css = str_replace( "\0", '', $css );

		// Remove JavaScript URLs and expressions
		$css = preg_replace( '/javascript\s*:/i', '', $css );
		$css = preg_replace( '/expression\s*\(/i', '', $css );
		$css = preg_replace( '/\bvbscript\s*:/i', '', $css );
		$css = preg_replace( '/-moz-binding\s*:/i', '', $css );
		$css = preg_replace( '/@import\b/i', '', $css );

		// Only allow data: URIs with safe image MIME types (not svg+xml due to XSS risk)
		$css = preg_replace_callback(
			'/url\s*\(\s*[\'"]?\s*data:([^)]*)\s*[\'"]?\s*\)/i',
			function ( $matches ) {
				$data_content = $matches[1];
				if ( preg_match( '#^image/(png|jpeg|gif|webp)#i', $data_content ) ) {
					return $matches[0]; // Allow safe image data URIs
				}
				return ''; // Block everything else
			},
			$css
		);

		// Limit length
		if ( strlen( $css ) > RIVIANTRACKR_CUSTOM_CSS_MAX_LENGTH ) {
			$css = substr( $css, 0, RIVIANTRACKR_CUSTOM_CSS_MAX_LENGTH );
		}

		return $css;
	}

	/**
	 * Intelligently truncate text at sentence boundaries.
	 *
	 * @param string $text  Text to truncate.
	 * @param int    $limit Maximum length in characters.
	 * @return string Truncated text.
	 */
	public function smart_truncate( string $text, int $limit ): string {
		if ( empty( $text ) ) {
			return '';
		}

		if ( $this->safe_substr( $text, 0, $limit ) === $text ) {
			return $text;
		}

		$truncated = $this->safe_substr( $text, 0, $limit );

		$sentence_endings  = array( '. ', '! ', '? ', '."', '!"', '?"', ".'", "!'", "?'" );
		$last_sentence_pos = 0;

		foreach ( $sentence_endings as $ending ) {
			$pos = strrpos( $truncated, $ending );
			if ( $pos !== false && $pos > $last_sentence_pos ) {
				$last_sentence_pos = $pos + strlen( $ending );
			}
		}

		if ( $last_sentence_pos > 0 && $last_sentence_pos >= ( $limit * 0.5 ) ) {
			return trim( $this->safe_substr( $truncated, 0, $last_sentence_pos ) );
		}

		$last_space = strrpos( $truncated, ' ' );
		if ( $last_space !== false && $last_space >= ( $limit * 0.7 ) ) {
			return trim( $this->safe_substr( $truncated, 0, $last_space ) ) . '...';
		}

		return $truncated . '...';
	}

	/**
	 * Multibyte-safe substr wrapper.
	 *
	 * @param string $text   Input text.
	 * @param int    $start  Start position.
	 * @param int    $length Length.
	 * @return string Substring.
	 */
	public function safe_substr( string $text, int $start, int $length ): string {
		if ( function_exists( 'mb_substr' ) ) {
			return mb_substr( $text, $start, $length );
		}
		return substr( $text, $start, $length );
	}
}
