<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use RivianTrackr\AISearchSummary\ApiHandler;

/**
 * Tests for the ApiHandler class.
 *
 * Covers prompt building, post formatting, Anthropic response
 * normalization, and AI content parsing.
 */
class ApiHandlerTest extends TestCase {

	private ApiHandler $handler;

	protected function setUp(): void {
		$this->handler = new ApiHandler();
	}

	/**
	 * Invoke the private normalize_anthropic_response() method.
	 */
	private function normalize( array $api_data ): array {
		$method = new ReflectionMethod( ApiHandler::class, 'normalize_anthropic_response' );
		return $method->invoke( $this->handler, $api_data );
	}

	// --- System Prompt Building ---

	public function test_system_prompt_includes_site_name(): void {
		$prompt = $this->handler->build_system_prompt( 'RivianTrackr' );
		$this->assertStringContainsString( 'RivianTrackr', $prompt );
	}

	public function test_system_prompt_includes_site_description(): void {
		$prompt = $this->handler->build_system_prompt( 'RivianTrackr', 'Rivian news and reviews' );
		$this->assertStringContainsString( 'Rivian news and reviews', $prompt );
	}

	public function test_system_prompt_contains_json_format(): void {
		$prompt = $this->handler->build_system_prompt( 'Test Site' );
		$this->assertStringContainsString( 'answer_html', $prompt );
		$this->assertStringContainsString( 'results', $prompt );
	}

	public function test_system_prompt_mentions_no_follow_up(): void {
		$prompt = $this->handler->build_system_prompt( 'Test Site' );
		$this->assertStringContainsString( 'Never ask follow-up questions', $prompt );
	}

	// --- Post Formatting ---

	public function test_formats_single_post(): void {
		$posts = array(
			array(
				'id'      => 1,
				'title'   => 'Test Post',
				'url'     => 'https://example.com/test',
				'type'    => 'post',
				'content' => 'Some content here.',
				'date'    => '2025-01-01',
			),
		);
		$output = $this->handler->format_posts_for_prompt( $posts );

		$this->assertStringContainsString( 'ID: 1', $output );
		$this->assertStringContainsString( 'Title: Test Post', $output );
		$this->assertStringContainsString( 'URL: https://example.com/test', $output );
		$this->assertStringContainsString( 'Type: post', $output );
		$this->assertStringContainsString( 'Published: 2025-01-01', $output );
		$this->assertStringContainsString( 'Content: Some content here.', $output );
		$this->assertStringContainsString( '-----', $output );
	}

	public function test_formats_post_without_date(): void {
		$posts = array(
			array(
				'id'      => 2,
				'title'   => 'No Date Post',
				'url'     => 'https://example.com/no-date',
				'type'    => 'page',
				'content' => 'Page content.',
			),
		);
		$output = $this->handler->format_posts_for_prompt( $posts );
		$this->assertStringNotContainsString( 'Published:', $output );
	}

	public function test_formats_multiple_posts(): void {
		$posts = array(
			array( 'id' => 1, 'title' => 'First', 'url' => 'https://a.com', 'type' => 'post', 'content' => 'A' ),
			array( 'id' => 2, 'title' => 'Second', 'url' => 'https://b.com', 'type' => 'post', 'content' => 'B' ),
		);
		$output = $this->handler->format_posts_for_prompt( $posts );
		$this->assertStringContainsString( 'Title: First', $output );
		$this->assertStringContainsString( 'Title: Second', $output );
		$this->assertSame( 2, substr_count( $output, '-----' ) );
	}

	// --- Anthropic Response Normalization ---

	public function test_normalize_restores_prefilled_brace(): void {
		// The request prefills the assistant turn with '{', so the API
		// response text continues without it.
		$normalized = $this->normalize( array(
			'content'     => array(
				array( 'type' => 'text', 'text' => '"answer_html":"<p>Hi</p>","results":[]}' ),
			),
			'stop_reason' => 'end_turn',
		) );

		$content = $normalized['choices'][0]['message']['content'];
		$this->assertSame( '{', $content[0] );
		$this->assertIsArray( json_decode( $content, true ) );
	}

	public function test_normalize_does_not_double_brace_full_json(): void {
		$normalized = $this->normalize( array(
			'content'     => array(
				array( 'type' => 'text', 'text' => '{"answer_html":"<p>Hi</p>","results":[]}' ),
			),
			'stop_reason' => 'end_turn',
		) );

		$content = $normalized['choices'][0]['message']['content'];
		$this->assertIsArray( json_decode( $content, true ) );
	}

	public function test_normalize_maps_max_tokens_to_length(): void {
		$normalized = $this->normalize( array(
			'content'     => array(
				array( 'type' => 'text', 'text' => '"answer_html":"<p>cut off' ),
			),
			'stop_reason' => 'max_tokens',
		) );

		$this->assertSame( 'length', $normalized['choices'][0]['finish_reason'] );
	}

	public function test_normalize_leaves_empty_content_empty(): void {
		$normalized = $this->normalize( array(
			'content'     => array(),
			'stop_reason' => 'end_turn',
		) );

		$this->assertSame( '', $normalized['choices'][0]['message']['content'] );
	}

	// --- AI Content Parsing ---

	public function test_parse_valid_response(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '{"answer_html":"<p>Hello</p>","results":[]}',
						'refusal' => null,
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNotNull( $result );
		$this->assertSame( '<p>Hello</p>', $result['answer_html'] );
		$this->assertSame( array(), $result['results'] );
		$this->assertSame( '', $error );
	}

	public function test_parse_response_with_results(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '{"answer_html":"<p>Test</p>","results":[{"id":1,"title":"Post","url":"https://test.com","excerpt":"Excerpt","type":"post"}]}',
						'refusal' => null,
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNotNull( $result );
		$this->assertCount( 1, $result['results'] );
		$this->assertSame( 1, $result['results'][0]['id'] );
	}

	public function test_parse_detects_model_refusal(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '',
						'refusal' => 'I cannot answer this.',
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNull( $result );
		$this->assertStringContainsString( 'declined', $error );
	}

	public function test_parse_handles_empty_content(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '',
						'refusal' => null,
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNull( $result );
		$this->assertNotEmpty( $error );
	}

	public function test_parse_handles_content_filter(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '',
						'refusal' => null,
					),
					'finish_reason' => 'content_filter',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNull( $result );
		$this->assertStringContainsString( 'content policy', $error );
	}

	public function test_parse_handles_length_truncation(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '',
						'refusal' => null,
					),
					'finish_reason' => 'length',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNull( $result );
		$this->assertStringContainsString( 'truncated', $error );
	}

	public function test_parse_extracts_json_from_markdown(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => "Here is the response:\n```json\n{\"answer_html\":\"<p>Found it</p>\",\"results\":[]}\n```",
						'refusal' => null,
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNotNull( $result );
		$this->assertSame( '<p>Found it</p>', $result['answer_html'] );
	}

	public function test_parse_handles_double_encoded_json(): void {
		$inner_json = json_encode( array(
			'answer_html' => '<p>Real answer</p>',
			'results'     => array(),
		) );
		$outer_json = json_encode( array(
			'answer_html' => $inner_json,
			'results'     => array(),
		) );

		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => $outer_json,
						'refusal' => null,
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNotNull( $result );
		$this->assertSame( '<p>Real answer</p>', $result['answer_html'] );
	}

	public function test_parse_provides_default_for_missing_answer_html(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '{"results":[]}',
						'refusal' => null,
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNotNull( $result );
		$this->assertStringContainsString( 'did not return a valid answer', $result['answer_html'] );
	}

	public function test_parse_provides_default_for_missing_results(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '{"answer_html":"<p>Test</p>"}',
						'refusal' => null,
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNotNull( $result );
		$this->assertSame( array(), $result['results'] );
	}

	public function test_parse_invalid_json_returns_error(): void {
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => 'this is not json at all',
						'refusal' => null,
					),
					'finish_reason' => 'stop',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNull( $result );
		$this->assertStringContainsString( 'parse', $error );
	}

	public function test_parse_truncated_json_reports_truncation(): void {
		// A response cut off mid-JSON at the max_tokens limit must surface
		// the truncation instead of a generic parse failure.
		$response = array(
			'choices' => array(
				array(
					'message' => array(
						'content' => '{"answer_html":"<p>This answer was cut off mid-sent',
						'refusal' => null,
					),
					'finish_reason' => 'length',
				),
			),
		);

		$error  = '';
		$result = $this->handler->parse_ai_content( $response, $error );

		$this->assertNull( $result );
		$this->assertStringContainsString( 'truncated', $error );
		$this->assertStringContainsString( 'Max Response Tokens', $error );
	}
}
