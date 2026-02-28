<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use RivianTrackr\AISearchSummary\ApiHandler;

/**
 * Tests for the ApiHandler class.
 *
 * Covers reasoning model detection, prompt building, post formatting,
 * and AI content parsing.
 */
class ApiHandlerTest extends TestCase {

	private ApiHandler $handler;

	protected function setUp(): void {
		$this->handler = new ApiHandler();
	}

	// --- Reasoning Model Detection ---

	public function test_o1_is_reasoning_model(): void {
		$this->assertTrue( ApiHandler::is_reasoning_model( 'o1' ) );
		$this->assertTrue( ApiHandler::is_reasoning_model( 'o1-preview' ) );
		$this->assertTrue( ApiHandler::is_reasoning_model( 'o1-mini' ) );
	}

	public function test_o3_is_reasoning_model(): void {
		$this->assertTrue( ApiHandler::is_reasoning_model( 'o3' ) );
		$this->assertTrue( ApiHandler::is_reasoning_model( 'o3-mini' ) );
	}

	public function test_o4_is_reasoning_model(): void {
		$this->assertTrue( ApiHandler::is_reasoning_model( 'o4-mini' ) );
	}

	public function test_gpt4o_is_not_reasoning_model(): void {
		$this->assertFalse( ApiHandler::is_reasoning_model( 'gpt-4o' ) );
		$this->assertFalse( ApiHandler::is_reasoning_model( 'gpt-4o-mini' ) );
	}

	public function test_gpt4_is_not_reasoning_model(): void {
		$this->assertFalse( ApiHandler::is_reasoning_model( 'gpt-4' ) );
		$this->assertFalse( ApiHandler::is_reasoning_model( 'gpt-4-turbo' ) );
	}

	public function test_claude_is_not_reasoning_model(): void {
		$this->assertFalse( ApiHandler::is_reasoning_model( 'claude-sonnet-4-6' ) );
		$this->assertFalse( ApiHandler::is_reasoning_model( 'claude-opus-4-6' ) );
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

	// --- AI Content Parsing ---

	public function test_parse_valid_openai_response(): void {
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
}
