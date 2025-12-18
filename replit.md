# GigSafe Job Board

## Overview
GigSafe Job Board is a specialized job aggregator for delivery driver and logistics positions, featuring over 1,186 jobs from 10 major companies including Amazon DSP, Airspace, and GoPuff. Its primary purpose is to help delivery drivers and logistics workers efficiently find relevant job opportunities through advanced search, filtering capabilities, and a user-friendly interface. The project aims to be the go-to platform for logistics employment, offering both scraped and user-submitted job listings.

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
-   **Advanced Search & Filtering:** Comprehensive search across job attributes, location (state/city), vehicle type, and certifications.
-   **Job Alerts & Subscriptions:** Users can subscribe to job alerts and optionally upload certifications.
-   **Job Posting Form:** Allows users to submit job listings, which are visible for 24 hours.
-   **Admin Dashboard:** Provides tools for viewing subscribers, managing user-submitted jobs (including hide/unhide functionality), and accessing detailed analytics with time-series charts (e.g., clicks over time).
-   **Responsive Design:** Optimized for mobile, tablet, and desktop experiences.
-   **Infinite Scroll Pagination:** For efficient job browsing.

### Database Schema (Shared)
-   **jobs table:**
    -   `id` (Primary Key)
    -   `submitted_at` (Timestamp, NULL for scraped jobs)
    -   `hidden` (Boolean, 0/1, for `user_jobs.db` only)
    -   `job_url`, `title`, `company`, `city`, `state`, `address`, `description`, `pay`, `general_requirements`, `schedule_details`, `benefits`, `vehicle_requirements`, `insurance_requirement`.

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