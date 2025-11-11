# GigSafe Job Board

## Overview
GigSafe Job Board is a specialized job aggregator for delivery driver and logistics positions, featuring over 2,766 jobs from multiple companies including Amazon DSP, Airspace, and GoPuff. Its primary purpose is to help delivery drivers and logistics workers efficiently find relevant job opportunities through advanced search, filtering capabilities, and a user-friendly interface. The project aims to be the go-to platform for logistics employment, offering both scraped and user-submitted job listings.

## Recent Changes

### November 11, 2025
-   **Stable Hash-Based Job IDs:** Implemented production-ready database import system using MD5 hash-based stable IDs:
    -   **ID Generation:** Job IDs are now 10-character hex strings (e.g., `37fa105c2e`) derived from MD5 hash of `job_url`, ensuring same job always gets same ID across imports
    -   **Analytics Preservation:** Stable IDs allow analytics (clicks, impressions, CTR) to persist across database refreshes without orphaned data
    -   **Import Scripts:** Created automated import pipeline in `scripts/` directory:
        - `import_with_stable_ids.js`: Main import script with transaction-based batch processing, data validation, duplicate detection
        - `backup_analytics.js`: Backs up subscribers, certifications, and non-job analytics events
        - `restore_analytics.js`: Restores analytics infrastructure to newly imported database
        - `verify_database.js`: Validates database integrity and ID format consistency
        - `test_id_stability.js`: Confirms IDs regenerate consistently from URLs
    -   **Production Import:** Successfully imported 2,766 jobs (up from 1,186) with stable IDs, skipped 190 invalid jobs missing required fields
    -   **Clean Analytics Start:** Cleared job_click and job_impression events for fresh production baseline while preserving subscriber/certification data
    -   **Import Workflow:** Standard procedure is: backup → import → restore → verify → restart
-   **Individual Job Analytics Dashboard:** Implemented comprehensive drill-down analytics feature for admin portal:
    -   **Search & Filter:** Added real-time search box above Popular Job Clicks table to filter by job title, company, or location
    -   **Click-to-Analyze:** Made all job rows clickable to open detailed analytics modal
    -   **Analytics Modal:** Shows individual job performance with Views, Clicks, and Click-Through Rate (CTR)
    -   **Time Range Selector:** Support for 24 hours, 7 days, 30 days, and all-time analytics
    -   **Dual-Axis Chart:** Chart.js visualization showing views vs clicks over time with separate Y-axes
    -   **Backend API:** New `/api/admin/analytics/job/:jobId` endpoint with time range filtering and admin authentication
    -   **Job Impression Tracking:** Implemented Intersection Observer-based tracking that records when job cards become visible (50% threshold), with batching (max 20 impressions per 5 seconds) and session-based de-duplication to optimize performance
-   **CORS Development Fix:** Updated CORS middleware to allow `*.replit.dev` URLs in development mode (when `REPL_ID` is set but not deployed). Production deployments still enforce strict CORS with approved domains only. This enables admin access during development while maintaining production security.
-   **Session Cookie Security Enhancement:** Admin session cookies now automatically use secure flag (HTTPS-only) when running on Replit (detects `REPLIT_DEPLOYMENT` or `REPL_ID`), preventing session hijacking without requiring manual `NODE_ENV=production` configuration.

### November 10, 2025
-   **Production Security Hardening:** Implemented comprehensive security improvements for production launch:
    -   **Database Protection:** Added `outputs/` directory to `.gitignore` to prevent accidental commit of sensitive data (sessions.db, user_jobs.db, master_jobs.db)
    -   **Password Validation:** Added startup validation requiring minimum 8 characters for ADMIN_PASSWORD environment variable
    -   **CORS Configuration:** Implemented custom CORS middleware applied only to `/api/*` routes. Validates Origin header when present against allowlist, allows same-origin requests without Origin header (browser standard behavior). Production deployments enforce strict domain validation. Development mode allows `*.replit.dev` URLs.
    -   **Security Logging:** All CORS violations and suspicious activity logged to `logs/security.log`

### November 7, 2025
-   **Gold Sash Fix:** Fixed the gold corner sash/banner that appears on user-submitted job tiles. The frontend was checking for `job.is_user_submitted` but the API returns `job.submitted_at`, causing the sash to never appear. Updated the condition to check for `job.submitted_at` instead.
-   **CSS Error Fix:** Corrected CSS syntax error in testimonial card pseudo-element where a curly quote character was used instead of a straight quote, which was causing LSP parsing errors.

### November 5, 2025
-   **Certification Requirements Feature:** Added support for filtering jobs by required certifications (HIPAA, BPP, TWIC, TSA, STA, HAZMAT). Jobs now display certification badges with consistent color-coded styling on job cards for easy identification.
-   **Consistent Color-Coded Tags:** Implemented visual color mapping system where each certification and vehicle type gets a specific, consistent color across all job listings. For example, HIPAA is always soft lavender, TSA is always light orange. This enables quick visual scanning without reading every tag.
-   **Auto-Trigger Search:** Implemented instant search filtering - selecting or removing a certification automatically triggers job search without requiring a manual "Search Jobs" button click for improved UX.
-   **Database Schema Update:** Added `certifications_required` column to both `master_jobs.db` and `user_jobs.db` to store comma-separated certification requirements.
-   **Enhanced Filtering:** Updated the certifications filter to search the dedicated `certifications_required` field instead of generic description/benefits fields for more accurate results.
-   **Database Refresh:** Imported new master database with 1,186 jobs, 18 of which have specific certification requirements.

## User Preferences
None documented yet.

## System Architecture

### Tech Stack
-   **Frontend:** Vanilla HTML/CSS/JavaScript
-   **Backend:** Express.js API server
-   **Database:** SQLite (using `better-sqlite3`)
-   **Analytics:** PostHog (for user behavior)

### Core System Design
-   **Unified Server:** Express.js serves both static frontend assets and API endpoints on Port 5000.
-   **Dual-Database System:**
    -   `user_jobs.db`: Stores user-submitted job postings, persisting independently and featuring a `submitted_at` timestamp. These jobs can be hidden by admins.
    -   `master_jobs.db`: Contains scraped job listings. This database can be refreshed without impacting user-submitted jobs. Scraped jobs have `submitted_at = NULL`.
    -   Jobs from both databases are merged via SQL `UNION ALL` with `ATTACH DATABASE` for public display, ensuring user jobs appear first.
-   **Data Storage:** User certification uploads are stored securely in `uploads/certifications/` and are not publicly accessible, requiring admin authentication for download.
-   **Analytics System:** Custom event tracking (page visits, searches, filters, job clicks) is implemented using an `analytics_events` table in the master database, with session-based de-duplication.
-   **Admin Portal:** A secure, password-protected Express.js session-based authentication system provides access to an admin dashboard for managing subscribers, submitted jobs, and analytics. Requires `ADMIN_PASSWORD` and `ADMIN_SESSION_SECRET` environment variables.

### Key Features
-   **Advanced Search & Filtering:** Comprehensive search across job attributes, location (state/city), vehicle type, and certifications. The certifications filter searches the `certifications_required` field and supports 6 certification types: HIPAA, BPP, TWIC, TSA, STA, and HAZMAT.
-   **Certification Badges:** Jobs with certification requirements display purple gradient badges on job cards for easy visual identification.
-   **Gold Sash Visual Indicator:** User-submitted jobs (uploaded through the job posting form) display a distinctive gold corner sash in the top-left of job cards to differentiate them from scraped job listings.
-   **Job Alerts & Subscriptions:** Users can subscribe to job alerts and optionally upload certifications.
-   **Job Posting Form:** Allows users to submit job listings with optional certification requirements, which are visible for 24 hours.
-   **Admin Dashboard:** Provides tools for viewing subscribers, managing user-submitted jobs (including hide/unhide functionality), and accessing detailed analytics with time-series charts (e.g., clicks over time).
-   **Responsive Design:** Optimized for mobile, tablet, and desktop experiences.
-   **Infinite Scroll Pagination:** For efficient job browsing.

### Database Schema (Shared)
-   **jobs table:**
    -   `id` (Primary Key, TEXT - 10-character hex hash derived from job_url for stability across imports)
    -   `submitted_at` (Timestamp, NULL for scraped jobs, NOT NULL for user-submitted jobs)
    -   `hidden` (Boolean, 0/1, for `user_jobs.db` only)
    -   `certifications_required` (TEXT, comma-separated list of required certifications: HIPAA, BPP, TWIC, TSA, STA, HAZMAT)
    -   `job_url`, `title`, `company`, `city`, `state`, `address`, `description`, `pay`, `general_requirements`, `schedule_details`, `benefits`, `vehicle_requirements`, `insurance_requirement`, `source_company`, `scraped_at`.

### Database Schema (Master Database Only)
-   **subscribers:** Email subscriptions.
-   **subscriber_certifications:** Certification files linked to subscribers.
-   **analytics_events:** Stores event type, data, and session ID for tracking.

### UI/UX Decisions
-   Frontend built with vanilla HTML/CSS/JavaScript for performance and control.
-   Responsive design principles applied for consistent experience across devices.
-   Admin dashboard includes interactive charts (Chart.js) for visualizing analytics data.

## External Dependencies
-   **PostHog:** Integrated for user behavior analytics.
-   **Chart.js:** Used for data visualization within the admin analytics dashboard.
-   **SQLite (`better-sqlite3`):** Database engine for both `user_jobs.db` and `master_jobs.db`.
-   **Express.js:** Web application framework for the backend API and serving static files.