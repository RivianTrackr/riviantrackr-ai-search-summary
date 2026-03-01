<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use RivianTrackr\AISearchSummary\InputValidator;

/**
 * Tests for the InputValidator class.
 *
 * Covers SQL injection detection, spam filtering, custom CSS sanitization,
 * and text truncation.
 */
class InputValidatorTest extends TestCase {

	private InputValidator $validator;

	protected function setUp(): void {
		$this->validator = new InputValidator();
	}

	// --- SQL Injection Detection ---

	public function test_detects_union_select_injection(): void {
		$this->assertTrue( $this->validator->is_sql_injection_attempt( "' UNION SELECT * FROM users --" ) );
	}

	public function test_detects_select_from_injection(): void {
		$this->assertTrue( $this->validator->is_sql_injection_attempt( 'SELECT password FROM wp_users' ) );
	}

	public function test_detects_drop_table_injection(): void {
		$this->assertTrue( $this->validator->is_sql_injection_attempt( '; DROP TABLE wp_posts;' ) );
	}

	public function test_detects_stacked_query_injection(): void {
		$this->assertTrue( $this->validator->is_sql_injection_attempt( "'; DELETE FROM wp_options; --" ) );
	}

	public function test_detects_sleep_injection(): void {
		$this->assertTrue( $this->validator->is_sql_injection_attempt( "' OR SLEEP(5) --" ) );
	}

	public function test_detects_information_schema(): void {
		$this->assertTrue( $this->validator->is_sql_injection_attempt( 'information_schema.tables' ) );
	}

	public function test_detects_url_encoded_injection(): void {
		$this->assertTrue( $this->validator->is_sql_injection_attempt( '%27%20UNION%20SELECT%20*%20FROM%20users' ) );
	}

	public function test_detects_excessive_special_characters(): void {
		$this->assertTrue( $this->validator->is_sql_injection_attempt( "'''\"\"\"((()))||===;;%%%" ) );
	}

	public function test_allows_normal_search_queries(): void {
		$this->assertFalse( $this->validator->is_sql_injection_attempt( 'Rivian R1T review 2025' ) );
	}

	public function test_allows_queries_with_numbers(): void {
		$this->assertFalse( $this->validator->is_sql_injection_attempt( 'R1S price under $50000' ) );
	}

	public function test_allows_queries_with_apostrophes(): void {
		$this->assertFalse( $this->validator->is_sql_injection_attempt( "what's new in Rivian" ) );
	}

	// --- Spam Query Detection ---

	public function test_detects_url_spam(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'visit https://spam-site.com now' ) );
	}

	public function test_detects_www_spam(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'check www.spam.com' ) );
	}

	public function test_detects_email_spam(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'contact spammer@evil.com' ) );
	}

	public function test_detects_phone_number_spam(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'call 1234567890 now' ) );
	}

	public function test_detects_repeated_characters(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'aaaaaaaaa' ) );
	}

	public function test_detects_repeated_words(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'buy buy buy buy buy' ) );
	}

	public function test_detects_viagra_spam(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'buy cheap viagra' ) );
	}

	public function test_detects_casino_spam(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'best casino bonus' ) );
	}

	public function test_detects_scanner_probes(): void {
		$this->assertTrue( $this->validator->is_spam_query( 'DOCUMENT_ROOT' ) );
		$this->assertTrue( $this->validator->is_spam_query( 'QUERY_STRING test' ) );
		$this->assertTrue( $this->validator->is_spam_query( 'HTTP_USER_AGENT' ) );
	}

	public function test_detects_high_non_alpha_ratio(): void {
		$this->assertTrue( $this->validator->is_spam_query( '!@#$%^&*()_+{}' ) );
	}

	public function test_blocklist_works(): void {
		$options = array( 'spam_blocklist' => "bad term\nblocked phrase" );
		$this->assertTrue( $this->validator->is_spam_query( 'this contains bad term here', $options ) );
	}

	public function test_allows_normal_queries(): void {
		$this->assertFalse( $this->validator->is_spam_query( 'Rivian R1T charging speed' ) );
	}

	public function test_allows_product_queries(): void {
		$this->assertFalse( $this->validator->is_spam_query( 'best electric truck 2025' ) );
	}

	// --- Off-Topic Query Detection ---

	public function test_off_topic_allows_all_when_no_keywords(): void {
		$this->assertFalse( $this->validator->is_off_topic_query( 'msi monitor amazon portugal' ) );
	}

	public function test_off_topic_allows_all_when_keywords_empty_string(): void {
		$options = array( 'relevance_keywords' => '' );
		$this->assertFalse( $this->validator->is_off_topic_query( 'costco credit card', $options ) );
	}

	public function test_off_topic_blocks_unrelated_query(): void {
		$options = array( 'relevance_keywords' => "rivian\nr1t\nr1s\nev\nelectric vehicle" );
		$this->assertTrue( $this->validator->is_off_topic_query( 'msi monitor amazon portugal', $options ) );
	}

	public function test_off_topic_blocks_person_name(): void {
		$options = array( 'relevance_keywords' => "rivian\nr1t\nr1s" );
		$this->assertTrue( $this->validator->is_off_topic_query( 'LOOMIS PATRICK', $options ) );
	}

	public function test_off_topic_blocks_unrelated_product(): void {
		$options = array( 'relevance_keywords' => "rivian\nr1t\nr1s\nelectric vehicle" );
		$this->assertTrue( $this->validator->is_off_topic_query( 'costco credit card application', $options ) );
	}

	public function test_off_topic_blocks_cable_product(): void {
		$options = array( 'relevance_keywords' => "rivian\nr1t\nr1s" );
		$this->assertTrue( $this->validator->is_off_topic_query( 'Cable HDMI a VGA 1.8M', $options ) );
	}

	public function test_off_topic_allows_rivian_query(): void {
		$options = array( 'relevance_keywords' => "rivian\nr1t\nr1s\nev\nelectric vehicle" );
		$this->assertFalse( $this->validator->is_off_topic_query( 'Rivian R1T review 2025', $options ) );
	}

	public function test_off_topic_allows_ev_keyword(): void {
		$options = array( 'relevance_keywords' => "rivian\nr1t\nr1s\nev\nelectric vehicle" );
		$this->assertFalse( $this->validator->is_off_topic_query( 'best ev charging stations', $options ) );
	}

	public function test_off_topic_allows_partial_match(): void {
		$options = array( 'relevance_keywords' => "rivian\nbattery" );
		$this->assertFalse( $this->validator->is_off_topic_query( 'rivian battery replacement cost', $options ) );
	}

	public function test_off_topic_case_insensitive(): void {
		$options = array( 'relevance_keywords' => "Rivian\nR1T" );
		$this->assertFalse( $this->validator->is_off_topic_query( 'rivian delivery update', $options ) );
	}

	public function test_off_topic_supports_comma_separated_keywords(): void {
		$options = array( 'relevance_keywords' => 'rivian, r1t, r1s, ev' );
		$this->assertFalse( $this->validator->is_off_topic_query( 'R1S range test', $options ) );
		$this->assertTrue( $this->validator->is_off_topic_query( 'costco credit card', $options ) );
	}

	public function test_off_topic_exact_word_match(): void {
		$options = array( 'relevance_keywords' => "ev" );
		$this->assertFalse( $this->validator->is_off_topic_query( 'best ev trucks 2025', $options ) );
	}

	// --- Validate Search Query (combined) ---

	public function test_rejects_empty_query(): void {
		$this->assertFalse( $this->validator->validate_search_query( '' ) );
	}

	public function test_rejects_whitespace_only(): void {
		$this->assertFalse( $this->validator->validate_search_query( '   ' ) );
	}

	public function test_rejects_too_short(): void {
		$this->assertFalse( $this->validator->validate_search_query( 'a' ) );
	}

	public function test_rejects_too_long(): void {
		$this->assertFalse( $this->validator->validate_search_query( str_repeat( 'a', 501 ) ) );
	}

	public function test_accepts_valid_query(): void {
		$this->assertTrue( $this->validator->validate_search_query( 'Rivian delivery timeline' ) );
	}

	public function test_rejects_sql_via_validate(): void {
		$this->assertFalse( $this->validator->validate_search_query( "'; DROP TABLE wp_posts; --" ) );
	}

	public function test_rejects_spam_via_validate(): void {
		$this->assertFalse( $this->validator->validate_search_query( 'buy cheap viagra online' ) );
	}

	// --- Custom CSS Sanitization ---

	public function test_css_removes_javascript_url(): void {
		$input  = 'background: url(javascript:alert(1))';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringNotContainsString( 'javascript', $output );
	}

	public function test_css_removes_expression(): void {
		$input  = 'width: expression(alert(1))';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringNotContainsString( 'expression', $output );
	}

	public function test_css_removes_vbscript(): void {
		$input  = 'background: url(vbscript:msgbox)';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringNotContainsString( 'vbscript', $output );
	}

	public function test_css_removes_moz_binding(): void {
		$input  = '-moz-binding: url(evil.xml#xss)';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringNotContainsString( '-moz-binding', $output );
	}

	public function test_css_removes_import(): void {
		$input  = '@import url(evil.css);';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringNotContainsString( '@import', $output );
	}

	public function test_css_blocks_svg_data_uri(): void {
		$input  = 'background: url(data:image/svg+xml;base64,PHN2Zy8+)';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringNotContainsString( 'svg+xml', $output );
	}

	public function test_css_allows_png_data_uri(): void {
		$input  = 'background: url(data:image/png;base64,iVBORw0KGgo=)';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringContainsString( 'data:image/png', $output );
	}

	public function test_css_allows_jpeg_data_uri(): void {
		$input  = 'background: url(data:image/jpeg;base64,abc=)';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringContainsString( 'data:image/jpeg', $output );
	}

	public function test_css_preserves_valid_rules(): void {
		$input  = '.my-class { color: red; font-size: 16px; }';
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertSame( $input, $output );
	}

	public function test_css_truncates_long_input(): void {
		$input  = str_repeat( 'a', RIVIANTRACKR_CUSTOM_CSS_MAX_LENGTH + 100 );
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertLessThanOrEqual( RIVIANTRACKR_CUSTOM_CSS_MAX_LENGTH, strlen( $output ) );
	}

	public function test_css_removes_null_bytes(): void {
		$input  = "color: red;\0 background: blue;";
		$output = $this->validator->sanitize_custom_css( $input );
		$this->assertStringNotContainsString( "\0", $output );
	}

	public function test_css_returns_empty_for_empty(): void {
		$this->assertSame( '', $this->validator->sanitize_custom_css( '' ) );
	}

	// --- Smart Truncate ---

	public function test_truncate_returns_short_text_unchanged(): void {
		$this->assertSame( 'Hello world', $this->validator->smart_truncate( 'Hello world', 100 ) );
	}

	public function test_truncate_cuts_at_sentence(): void {
		$text   = 'First sentence. Second sentence. Third sentence is longer here.';
		$result = $this->validator->smart_truncate( $text, 35 );
		$this->assertSame( 'First sentence. Second sentence.', $result );
	}

	public function test_truncate_falls_back_to_word_boundary(): void {
		$text   = 'This is a very long text without any period marks anywhere at all in here';
		$result = $this->validator->smart_truncate( $text, 40 );
		$this->assertStringEndsWith( '...', $result );
		$this->assertLessThanOrEqual( 43, strlen( $result ) ); // limit + "..."
	}

	public function test_truncate_returns_empty_for_empty(): void {
		$this->assertSame( '', $this->validator->smart_truncate( '', 100 ) );
	}
}
