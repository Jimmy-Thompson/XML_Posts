# GigSafe Job Board

## Overview
GigSafe Job Board is a specialized job aggregator designed to connect delivery drivers and logistics workers with relevant job opportunities. It features a large database of jobs from various companies like Amazon DSP, Airspace, GoPuff, and WARP Freight, offering advanced search, filtering capabilities, and a user-friendly interface. The project aims to become the leading platform for logistics employment, integrating both scraped and user-submitted job listings.

## User Preferences
None documented yet.

## System Architecture

### Core System Design
The project uses a unified Express.js server that handles both static frontend assets and API endpoints. It operates with a dual-database system, initially using SQLite (`user_jobs.db` for user submissions and `master_jobs.db` for scraped jobs), with a migration path to PostgreSQL for persistent storage. Jobs from both databases are merged for public display, prioritizing user-submitted listings. User certification uploads are stored securely and require admin authentication for access. A custom analytics system tracks user events, and an admin portal provides secure, password-protected access for managing subscriptions, jobs, and analytics.

### Key Features
-   **Advanced Search & Filtering:** Comprehensive search across job attributes, location, vehicle type, and specific certifications (HIPAA, BPP, TWIC, TSA, STA, HAZMAT). Filters like "Cargo/Sprinter Van" and "Box Truck" include smart logic to match related vehicle types.
-   **Visual Job Indicators:** Certification requirements are highlighted with color-coded badges, and user-submitted jobs are distinguished by a gold corner sash.
-   **Job Alerts & Subscriptions:** Users can subscribe to job alerts and upload certifications.
-   **Job Posting Form:** Allows users to submit job listings with optional certification requirements.
-   **Admin Dashboard:** Provides tools for managing subscribers, user-submitted jobs (including hide/unhide functionality), and detailed analytics with time-series charts. Features include individual job analytics with views, clicks, and CTR over various time ranges, powered by Intersection Observer-based impression tracking.
-   **Stable Job IDs:** Job IDs are 10-character hex strings derived from MD5 hashes of job URLs, ensuring stability across database imports for consistent analytics tracking.
-   **User Experience:** Features like auto-scroll to results after searching, instant search filtering upon selecting certifications, and infinite scroll pagination enhance usability.
-   **Security:** Includes measures like password validation for admin access, strict CORS configuration for production, session cookie security enhancements, and secure handling of sensitive data.

### Database Schema (Key Tables)

#### PostgreSQL (user_submitted_jobs)
-   **user_submitted_jobs table:** Contains `id` (serial primary key), `title`, `company`, `city`, `state`, `postalcode`, `address`, `description`, `pay`, `general_requirements`, `benefits`, `vehicle_requirements`, `insurance_requirement`, `certifications_required`, `schedule_details`, `submitted_at`, `job_url`, `hidden` (boolean), `admin_keep_visible` (boolean, default false - when true, job stays visible indefinitely regardless of 24-hour expiration).

#### SQLite (scraped jobs)
-   **jobs table:** Contains `id` (stable hash), `submitted_at`, `hidden`, `certifications_required`, `job_url`, `title`, `company`, `city`, `state`, `description`, `vehicle_requirements`, and other job-related fields.

#### Other Tables
-   **subscribers:** Stores email subscriptions.
-   **subscriber_certifications:** Links certification files to subscribers.
-   **analytics_events:** Records event type, data, and session ID for tracking user interactions.

### UI/UX Decisions
The frontend uses vanilla HTML/CSS/JavaScript for performance and control, adhering to responsive design principles. The admin dashboard incorporates interactive charts (Chart.js) for analytics visualization. Consistent color-coding is used for certifications and vehicle types for quick visual scanning.

## External Dependencies
-   **PostgreSQL:** Planned for persistent database storage (migration in progress).
-   **SQLite (`better-sqlite3`):** Currently used as the primary database engine.
-   **Express.js:** Web application framework for the backend API and serving static files.
-   **PostHog:** Integrated for user behavior analytics.
-   **Chart.js:** Used for data visualization within the admin analytics dashboard.
-   **Paperform:** Used for subscription redirects (e.g., `https://dnwfrabb.paperform.co/`).