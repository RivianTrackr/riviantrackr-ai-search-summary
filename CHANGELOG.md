# Changelog

All notable changes to AI Search Summary will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-08

### Added

#### Core Features
- AI-powered search summaries using OpenAI's GPT models (GPT-4o, GPT-4, GPT-3.5-turbo)
- Support for OpenAI reasoning models (o1, o3) with configurable toggle
- Non-blocking async loading - search results display immediately while AI summary loads
- Collapsible sources section showing articles used for summary generation
- Smart content truncation for optimal API usage

#### Admin Interface
- Comprehensive settings page with organized sections
- API key validation with test connection button
- Dynamic model selection populated from OpenAI API
- Custom CSS editor with syntax highlighting
- Color theming (background, text, accent, border colors)

#### Analytics & Monitoring
- Full analytics dashboard with daily statistics
- Success rate and cache performance tracking
- Top search queries ranking
- Error analysis and tracking
- CSV export for logs, daily stats, and feedback
- WordPress dashboard widget for quick stats overview

#### Performance & Caching
- Multi-tier caching system (server-side transients + browser session cache)
- Configurable cache TTL (1 minute to 24 hours)
- Namespace-based cache invalidation
- Manual cache clear functionality
- Smart API usage - skips calls when no matching posts exist

#### Rate Limiting & Security
- IP-based rate limiting (configurable requests per minute)
- Global AI call rate limiting
- Bot detection to prevent unnecessary API calls
- Security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, X-XSS-Protection)
- Secure API key storage via wp-config.php constant
- SQL injection prevention with prepared statements
- XSS prevention with proper output escaping
- Nonce verification for all admin actions

#### Widgets & Shortcodes
- Trending Searches sidebar widget with customizable appearance
- `[aiss_trending]` shortcode for embedding trending searches anywhere
- Configurable time periods, limits, colors, and titles

#### REST API
- `/wp-json/aiss/v1/summary` - Get AI summary for search queries
- `/wp-json/aiss/v1/log-session-hit` - Log frontend cache hits
- `/wp-json/aiss/v1/feedback` - Submit user feedback

#### Data Management
- Automatic log purging with configurable retention (7-365 days)
- Scheduled cleanup via WP-Cron
- GDPR-friendly design - no user identification stored
- IP hashing for feedback (not full IP storage)

#### User Experience
- Optional "Powered by OpenAI" badge
- Optional thumbs up/down feedback buttons
- Configurable sources display
- Responsive design
- Smooth loading animations

---

This is the first official release of AI Search Summary, consolidating all development work into a stable 1.0.0 version.
