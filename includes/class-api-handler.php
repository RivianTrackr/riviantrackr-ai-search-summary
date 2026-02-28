<?php
declare(strict_types=1);

namespace RivianTrackr\AISearchSummary;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles communication with OpenAI and Anthropic APIs.
 *
 * Includes prompt construction, request execution with retry logic,
 * and response normalization.
 */
class ApiHandler {

	/**
	 * Known reasoning models that require special token parameters.
	 */
	private const REASONING_MODELS = array( 'o1', 'o3', 'o4' );

	/**
	 * Check if a model is a reasoning model.
	 *
	 * @param string $model Model ID.
	 * @return bool
	 */
	public static function is_reasoning_model( string $model ): bool {
		foreach ( self::REASONING_MODELS as $prefix ) {
			if ( strpos( $model, $prefix ) === 0 ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Build the system prompt for AI search.
	 *
	 * @param string $site_name Site display name.
	 * @param string $site_desc Optional site description.
	 * @return string System message for the AI.
	 */
	public function build_system_prompt( string $site_name, string $site_desc = '' ): string {
		$desc_suffix = ! empty( $site_desc ) ? ', ' . $site_desc : '';

		return "You are the AI-powered search assistant built into {$site_name}{$desc_suffix}.
    You are part of the {$site_name} platform — users are reading your answers directly on the site. Speak as {$site_name}'s search assistant, not as a generic external AI.
    Use the provided posts as your entire knowledge base.
    Answer the user query based only on these posts.
    When referencing information, naturally attribute it to {$site_name} coverage (e.g. \"Based on {$site_name}'s reporting...\", \"As covered on {$site_name}...\", \"{$site_name} reported that...\"). Do not over-attribute — one or two natural references per answer is enough.
    Prefer newer posts over older ones when there is conflicting or overlapping information, especially for news, software updates, or product changes.
    If something is not covered, say that {$site_name} does not have that information yet instead of making something up.

    IMPORTANT: This is a one-way search interface - users cannot reply or provide clarification. Never ask follow-up questions, never ask the user to clarify, and never suggest they tell you more. Instead, provide the most comprehensive answer possible covering all likely interpretations of their query. If a query is ambiguous, briefly cover the most relevant possibilities.

    Always respond as a single JSON object using this structure:
    {
      \"answer_html\": \"HTML formatted summary answer for the user\",
      \"results\": [
         {
           \"id\": 123,
           \"title\": \"Post title\",
           \"url\": \"https://...\",
           \"excerpt\": \"Short snippet\",
           \"type\": \"post or page\"
         }
      ]
    }

    The results array should list up to 5 of the most relevant posts you used when creating the summary, so they can be shown as sources under the answer.";
	}

	/**
	 * Format posts into a text block for the AI prompt.
	 *
	 * @param array $posts Array of post data arrays.
	 * @return string Formatted text.
	 */
	public function format_posts_for_prompt( array $posts ): string {
		$text = '';
		foreach ( $posts as $p ) {
			$date = isset( $p['date'] ) ? $p['date'] : '';
			$text .= "ID: {$p['id']}\n";
			$text .= "Title: {$p['title']}\n";
			$text .= "URL: {$p['url']}\n";
			$text .= "Type: {$p['type']}\n";
			if ( $date ) {
				$text .= "Published: {$date}\n";
			}
			$text .= "Content: {$p['content']}\n";
			$text .= "-----\n";
		}
		return $text;
	}

	/**
	 * Call the OpenAI API with retry logic.
	 *
	 * @param string $api_key   API key.
	 * @param string $model     Model ID.
	 * @param string $query     User search query.
	 * @param array  $posts     Posts data for context.
	 * @param array  $options   Plugin options.
	 * @return array API response or array with 'error' key.
	 */
	public function call_openai( string $api_key, string $model, string $query, array $posts, array $options ): array {
		if ( empty( $api_key ) ) {
			return array( 'error' => 'API key is missing. Please configure the plugin settings.' );
		}

		$endpoint = 'https://api.openai.com/v1/chat/completions';

		$posts_text = $this->format_posts_for_prompt( $posts );
		$site_name  = ! empty( $options['site_name'] ) ? $options['site_name'] : get_bloginfo( 'name' );
		$site_desc  = ! empty( $options['site_description'] ) ? $options['site_description'] : '';

		$system_message = $this->build_system_prompt( $site_name, $site_desc );
		$user_message   = "User search query: {$query}\n\nHere are the posts from the site (with newer posts listed first where possible):\n\n{$posts_text}";

		$is_reasoning = self::is_reasoning_model( $model );

		$supports_response_format = (
			strpos( $model, 'gpt-4o' ) === 0 ||
			strpos( $model, 'gpt-4.1' ) === 0
		);

		$body = array(
			'model'    => $model,
			'messages' => array(
				array(
					'role'    => 'system',
					'content' => $system_message,
				),
				array(
					'role'    => 'user',
					'content' => $user_message,
				),
			),
		);

		$configured_tokens = isset( $options['max_tokens'] ) ? (int) $options['max_tokens'] : RIVIANTRACKR_MAX_TOKENS;

		if ( $is_reasoning ) {
			$body['max_completion_tokens'] = max( $configured_tokens, 16000 );
		} else {
			$body['max_tokens'] = $configured_tokens;
		}

		if ( ! $is_reasoning ) {
			$body['temperature'] = 0.2;
		}

		if ( $supports_response_format ) {
			$body['response_format'] = array( 'type' => 'json_object' );
		}

		$args = array(
			'headers' => array(
				'Authorization' => 'Bearer ' . $api_key,
				'Content-Type'  => 'application/json',
			),
			'body'    => wp_json_encode( $body ),
			'timeout' => isset( $options['request_timeout'] ) ? (int) $options['request_timeout'] : RIVIANTRACKR_API_TIMEOUT,
		);

		return $this->execute_with_retry(
			function () use ( $endpoint, $args ) {
				return $this->make_openai_request( $endpoint, $args );
			}
		);
	}

	/**
	 * Call the Anthropic Claude API with retry logic.
	 *
	 * @param string $api_key   API key.
	 * @param string $model     Model ID.
	 * @param string $query     User search query.
	 * @param array  $posts     Posts data for context.
	 * @param array  $options   Plugin options.
	 * @return array Normalized API response or array with 'error' key.
	 */
	public function call_anthropic( string $api_key, string $model, string $query, array $posts, array $options ): array {
		if ( empty( $api_key ) ) {
			return array( 'error' => 'API key is missing. Please configure the plugin settings.' );
		}

		$endpoint = 'https://api.anthropic.com/v1/messages';

		$posts_text = $this->format_posts_for_prompt( $posts );
		$site_name  = ! empty( $options['site_name'] ) ? $options['site_name'] : get_bloginfo( 'name' );
		$site_desc  = ! empty( $options['site_description'] ) ? $options['site_description'] : '';

		$system_message = $this->build_system_prompt( $site_name, $site_desc );
		$user_message   = "User search query: {$query}\n\nHere are the posts from the site (with newer posts listed first where possible):\n\n{$posts_text}";

		$configured_tokens = isset( $options['max_tokens'] ) ? (int) $options['max_tokens'] : RIVIANTRACKR_MAX_TOKENS;

		$body = array(
			'model'      => $model,
			'max_tokens' => $configured_tokens,
			'system'     => $system_message,
			'messages'   => array(
				array(
					'role'    => 'user',
					'content' => $user_message,
				),
			),
		);

		$args = array(
			'headers' => array(
				'x-api-key'         => $api_key,
				'anthropic-version' => RIVIANTRACKR_ANTHROPIC_API_VERSION,
				'Content-Type'      => 'application/json',
			),
			'body'    => wp_json_encode( $body ),
			'timeout' => isset( $options['request_timeout'] ) ? (int) $options['request_timeout'] : RIVIANTRACKR_API_TIMEOUT,
		);

		return $this->execute_with_retry(
			function () use ( $endpoint, $args ) {
				return $this->make_anthropic_request( $endpoint, $args );
			},
			true // normalize Anthropic response
		);
	}

	/**
	 * Execute an API request with retry logic.
	 *
	 * @param callable $request_fn         Function that returns a result array.
	 * @param bool     $normalize_anthropic Whether to normalize the response format.
	 * @return array API response.
	 */
	private function execute_with_retry( callable $request_fn, bool $normalize_anthropic = false ): array {
		$max_retries = 2;
		$attempt     = 0;
		$last_error  = null;

		while ( $attempt <= $max_retries ) {
			$result = $request_fn();

			if ( isset( $result['success'] ) && $result['success'] ) {
				$data = $result['data'];

				if ( $normalize_anthropic ) {
					$data = $this->normalize_anthropic_response( $data );
				}

				if ( $attempt > 0 ) {
					$data['_retry_count'] = $attempt;
					if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
						// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
						error_log( '[RivianTrackr AI Search Summary] Request succeeded after ' . $attempt . ' retry(ies)' );
					}
				}
				return $data;
			}

			$is_retryable = isset( $result['retryable'] ) && $result['retryable'];
			$last_error   = $result;

			if ( ! $is_retryable || $attempt >= $max_retries ) {
				break;
			}

			$delay = pow( 2, $attempt );
			sleep( $delay );
			$attempt++;

			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( '[RivianTrackr AI Search Summary] Retry attempt ' . ( $attempt + 1 ) . ' after ' . $delay . 's delay' );
			}
		}

		$error_msg = $last_error['error'] ?? 'Unknown error occurred.';
		if ( $attempt > 0 ) {
			$error_msg .= ' (after ' . ( $attempt + 1 ) . ' attempts)';
		}
		return array( 'error' => $error_msg );
	}

	/**
	 * Normalize Anthropic response to OpenAI-compatible format.
	 *
	 * @param array $api_data Raw Anthropic response.
	 * @return array OpenAI-compatible format.
	 */
	private function normalize_anthropic_response( array $api_data ): array {
		$content_text = '';
		if ( ! empty( $api_data['content'] ) && is_array( $api_data['content'] ) ) {
			foreach ( $api_data['content'] as $block ) {
				if ( isset( $block['type'] ) && $block['type'] === 'text' && isset( $block['text'] ) ) {
					$content_text .= $block['text'];
				}
			}
		}

		$stop_reason   = isset( $api_data['stop_reason'] ) ? $api_data['stop_reason'] : 'end_turn';
		$finish_reason = 'stop';
		if ( $stop_reason === 'max_tokens' ) {
			$finish_reason = 'length';
		}

		return array(
			'choices' => array(
				array(
					'message' => array(
						'content' => $content_text,
						'refusal' => null,
					),
					'finish_reason' => $finish_reason,
				),
			),
		);
	}

	/**
	 * Make an HTTP request to OpenAI.
	 *
	 * @param string $endpoint API endpoint URL.
	 * @param array  $args     wp_remote_post args.
	 * @return array{success: bool, data?: array, error?: string, retryable?: bool}
	 */
	private function make_openai_request( string $endpoint, array $args ): array {
		$response = wp_safe_remote_post( $endpoint, $args );

		if ( is_wp_error( $response ) ) {
			return $this->handle_connection_error( $response );
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		if ( $code < 200 || $code >= 300 ) {
			return $this->handle_http_error( $code, $body, 'OpenAI' );
		}

		return $this->parse_json_response( $body );
	}

	/**
	 * Make an HTTP request to Anthropic.
	 *
	 * @param string $endpoint API endpoint URL.
	 * @param array  $args     wp_remote_post args.
	 * @return array{success: bool, data?: array, error?: string, retryable?: bool}
	 */
	private function make_anthropic_request( string $endpoint, array $args ): array {
		$response = wp_safe_remote_post( $endpoint, $args );

		if ( is_wp_error( $response ) ) {
			return $this->handle_connection_error( $response );
		}

		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		if ( $code < 200 || $code >= 300 ) {
			// Anthropic uses 529 for overloaded
			if ( $code === 529 ) {
				return array(
					'success'   => false,
					'error'     => 'Anthropic API is temporarily overloaded. Please try again later.',
					'retryable' => true,
				);
			}
			return $this->handle_http_error( $code, $body, 'Anthropic' );
		}

		return $this->parse_json_response( $body );
	}

	/**
	 * Handle a WP_Error from wp_remote_post.
	 *
	 * @param \WP_Error $response WordPress error object.
	 * @return array Result array.
	 */
	private function handle_connection_error( \WP_Error $response ): array {
		$error_msg = $response->get_error_message();
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( '[RivianTrackr AI Search Summary] API request error: ' . $error_msg );
		}

		$is_timeout    = strpos( $error_msg, 'cURL error 28' ) !== false || strpos( $error_msg, 'timed out' ) !== false;
		$is_connection = strpos( $error_msg, 'cURL error 6' ) !== false || strpos( $error_msg, 'resolve host' ) !== false;

		if ( $is_timeout ) {
			return array(
				'success'   => false,
				'error'     => 'Request timed out. The AI service may be slow right now. Please try again.',
				'retryable' => true,
			);
		}
		if ( $is_connection ) {
			return array(
				'success'   => false,
				'error'     => 'Could not connect to AI service. Please check your internet connection.',
				'retryable' => true,
			);
		}

		return array(
			'success'   => false,
			'error'     => 'Could not connect to AI service. Please try again.',
			'retryable' => true,
		);
	}

	/**
	 * Handle an HTTP error response.
	 *
	 * @param int    $code     HTTP status code.
	 * @param string $body     Response body.
	 * @param string $provider Provider name for error messages.
	 * @return array Result array.
	 */
	private function handle_http_error( int $code, string $body, string $provider ): array {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( '[RivianTrackr AI Search Summary] ' . $provider . ' HTTP error ' . $code . ' body: ' . $body );
		}

		if ( $code === 429 ) {
			return array(
				'success'   => false,
				'error'     => $provider . ' rate limit exceeded. Please try again in a few moments.',
				'retryable' => true,
			);
		}

		if ( $code >= 500 && $code < 600 ) {
			return array(
				'success'   => false,
				'error'     => $provider . ' service temporarily unavailable. Please try again later.',
				'retryable' => true,
			);
		}

		if ( $code === 401 ) {
			return array(
				'success'   => false,
				'error'     => 'Invalid ' . $provider . ' API key. Please check your plugin settings.',
				'retryable' => false,
			);
		}

		if ( $code === 400 ) {
			return array(
				'success'   => false,
				'error'     => 'The request could not be processed. Please try a different search.',
				'retryable' => false,
			);
		}

		return array(
			'success'   => false,
			'error'     => 'AI service error. Please try again later.',
			'retryable' => false,
		);
	}

	/**
	 * Parse a JSON response body.
	 *
	 * @param string $body Response body.
	 * @return array Result array.
	 */
	private function parse_json_response( string $body ): array {
		$decoded = json_decode( $body, true );

		if ( json_last_error() !== JSON_ERROR_NONE ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( '[RivianTrackr AI Search Summary] Failed to decode response: ' . json_last_error_msg() );
			}
			return array(
				'success'   => false,
				'error'     => 'Could not understand AI response. Please try again.',
				'retryable' => true,
			);
		}

		return array(
			'success' => true,
			'data'    => $decoded,
		);
	}

	/**
	 * Parse the AI content from a normalized API response.
	 *
	 * Handles JSON extraction, nested JSON unwrapping, and validation.
	 *
	 * @param array  $api_response Normalized API response.
	 * @param string $ai_error     Output: error message if parsing fails.
	 * @return array|null Parsed data or null on failure.
	 */
	public function parse_ai_content( array $api_response, string &$ai_error ): ?array {
		// Check for model refusal
		if ( ! empty( $api_response['choices'][0]['message']['refusal'] ) ) {
			$ai_error = 'The AI model declined to answer this query.';
			return null;
		}

		// Get content from multiple possible locations
		$raw_content = null;
		if ( ! empty( $api_response['choices'][0]['message']['content'] ) ) {
			$raw_content = $api_response['choices'][0]['message']['content'];
		} elseif ( ! empty( $api_response['choices'][0]['text'] ) ) {
			$raw_content = $api_response['choices'][0]['text'];
		} elseif ( ! empty( $api_response['output'] ) ) {
			$raw_content = is_array( $api_response['output'] )
				? wp_json_encode( $api_response['output'] )
				: $api_response['output'];
		}

		if ( empty( $raw_content ) ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( '[RivianTrackr AI Search Summary] Empty response. Full API response: ' . wp_json_encode( $api_response ) );
			}
			$finish_reason = $api_response['choices'][0]['finish_reason'] ?? 'unknown';
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( '[RivianTrackr AI Search Summary] Empty response with finish_reason: ' . $finish_reason );
			}
			if ( $finish_reason === 'content_filter' ) {
				$ai_error = 'The response was filtered by content policy. Please try a different search.';
			} elseif ( $finish_reason === 'length' ) {
				$ai_error = 'The response was truncated. Please try a simpler search.';
			} else {
				$ai_error = 'AI summary is not available for this search. Please try again.';
			}
			return null;
		}

		// Decode JSON content
		if ( is_array( $raw_content ) ) {
			$decoded = $raw_content;
		} else {
			$decoded = json_decode( $raw_content, true );

			if ( json_last_error() !== JSON_ERROR_NONE ) {
				$first = strpos( $raw_content, '{' );
				$last  = strrpos( $raw_content, '}' );
				if ( $first !== false && $last !== false && $last > $first ) {
					$json_candidate = substr( $raw_content, $first, $last - $first + 1 );
					$decoded        = json_decode( $json_candidate, true );
				}
			}
		}

		if ( ! is_array( $decoded ) ) {
			$ai_error = 'Could not parse AI response. The service may be experiencing issues.';
			return null;
		}

		// Handle double-encoded JSON
		if ( isset( $decoded['answer_html'] ) && is_string( $decoded['answer_html'] ) ) {
			$inner = trim( $decoded['answer_html'] );
			if ( strlen( $inner ) > 0 && $inner[0] === '{' && strpos( $inner, '"answer_html"' ) !== false ) {
				$inner_decoded = json_decode( $inner, true );
				if ( json_last_error() === JSON_ERROR_NONE && is_array( $inner_decoded ) && isset( $inner_decoded['answer_html'] ) ) {
					$decoded = $inner_decoded;
				}
			}
		}

		if ( empty( $decoded['answer_html'] ) ) {
			$decoded['answer_html'] = '<p>AI summary did not return a valid answer.</p>';
		}

		if ( empty( $decoded['results'] ) || ! is_array( $decoded['results'] ) ) {
			$decoded['results'] = array();
		}

		return $decoded;
	}

	/**
	 * Test an OpenAI API key.
	 *
	 * @param string $api_key API key to test.
	 * @return array{success: bool, message: string, models?: string[]}
	 */
	public function test_openai_key( string $api_key ): array {
		$response = wp_safe_remote_get(
			'https://api.openai.com/v1/models',
			array(
				'headers' => array( 'Authorization' => 'Bearer ' . $api_key ),
				'timeout' => 15,
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'message' => 'Connection error: ' . $response->get_error_message(),
			);
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			return array(
				'success' => false,
				'message' => 'API returned HTTP ' . $code,
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || empty( $body['data'] ) ) {
			return array(
				'success' => false,
				'message' => 'Unexpected API response format.',
			);
		}

		$models = array();
		foreach ( $body['data'] as $m ) {
			if ( isset( $m['id'] ) ) {
				$models[] = $m['id'];
			}
		}
		sort( $models );

		return array(
			'success' => true,
			'message' => 'API key is valid.',
			'models'  => $models,
		);
	}

	/**
	 * Test an Anthropic API key.
	 *
	 * @param string $api_key API key to test.
	 * @return array{success: bool, message: string}
	 */
	public function test_anthropic_key( string $api_key ): array {
		$response = wp_safe_remote_post(
			'https://api.anthropic.com/v1/messages',
			array(
				'headers' => array(
					'x-api-key'         => $api_key,
					'anthropic-version' => RIVIANTRACKR_ANTHROPIC_API_VERSION,
					'Content-Type'      => 'application/json',
				),
				'body'    => wp_json_encode( array(
					'model'      => 'claude-haiku-4-5-20251001',
					'max_tokens' => 10,
					'messages'   => array(
						array(
							'role'    => 'user',
							'content' => 'Say "ok".',
						),
					),
				) ),
				'timeout' => 15,
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'success' => false,
				'message' => 'Connection error: ' . $response->get_error_message(),
			);
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code === 200 ) {
			return array(
				'success' => true,
				'message' => 'Anthropic API key is valid.',
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		$api_msg = $body['error']['message'] ?? ( 'HTTP ' . $code );

		return array(
			'success' => false,
			'message' => 'API error: ' . $api_msg,
		);
	}
}
