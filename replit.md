# GigSafe Job Board - Replit Project

## Overview
GigSafe Job Board is a job aggregator for delivery driver and logistics positions, featuring 1,186+ jobs from 10 companies including Amazon DSP, Airspace, GoPuff, and more.

**Purpose:** Help delivery drivers and logistics workers find relevant job opportunities with advanced search and filtering capabilities.

**Current State:** Fully functional job board with API backend and responsive frontend.

## Project Architecture

### Tech Stack
- **Frontend:** Vanilla HTML/CSS/JavaScript with modern design
- **Backend:** Express.js API server
- **Database:** SQLite (better-sqlite3)
- **Analytics:** PostHog (user behavior tracking)

### Structure
```
GigSafeJobBoard/
├── App/
│   ├── index.html             # Main frontend interface
│   ├── post-job.html          # Job posting form page
│   ├── admin-login.html       # Admin login page
│   ├── admin.html             # Admin dashboard
│   └── cities_by_state.json   # Location filter data
├── shared/
│   └── db.js                  # SQLite database connection
├── outputs/
│   └── master_database/
│       └── master_jobs.db     # Job database (SQLite)
├── uploads/
│   └── certifications/        # User certification uploads (NOT publicly accessible)
├── api-server.js              # Express API server with admin auth
└── package.json               # Dependencies and scripts
```

### Ports
- **Unified Server:** Port 5000 (Express.js serves both static frontend and API endpoints)

### Database Schema
- **jobs:** Job listings with title, company, location, requirements, benefits, etc. Includes `submitted_at` column to track user-submitted jobs for 24-hour visibility.
- **subscribers:** Email subscriptions for job alerts
- **subscriber_certifications:** Uploaded certification files
- **analytics_events:** Event tracking for visitor analytics (page visits, searches, filters, job clicks) with session IDs and timestamps

## Key Features
- Advanced search across job titles, descriptions, and requirements
- Location filtering by state and city
- Vehicle type filtering (Van, Box Truck, Car, etc.)
- Certification search functionality
- Job alerts subscription with certification upload
- **Job posting form** - Users can submit jobs that appear for 24 hours
- **Secure admin portal** - Password-protected dashboard to view subscribers, job submissions, and analytics
- **Custom analytics system** - Track page visits, searches, filters, and job clicks with session-based de-duplication
- Infinite scroll pagination
- Responsive design for mobile, tablet, and desktop

## API Endpoints

### GET /api/jobs
Fetch jobs with pagination and filtering.

Query Parameters:
- `page` - Page number (default: 1)
- `limit` - Jobs per page (default: 20)
- `keyword` - Search term for title/description/company
- `state` - Filter by state (e.g., "CA", "TX")
- `city` - Filter by city
- `vehicle` - Filter by vehicle requirement
- `certifications` - Comma-separated certification list

### POST /api/jobs
Submit a new job posting (visible for 24 hours).

Body (JSON):
- `job_url` (required) - Application URL
- `title` (required) - Job title
- `company` (required) - Company name
- `city` (required) - City
- `state` (required) - 2-letter state code
- `description` (required) - Job description
- `pay` (required) - Compensation details
- `address` - Full street address (optional)
- `general_requirements` - Job requirements (optional)
- `schedule_details` - Work schedule (optional)
- `benefits` - Benefits offered (optional)
- `vehicle_requirements` - Vehicle requirements (optional)
- `insurance_requirement` - Insurance requirements (optional)

### POST /api/subscribe
Subscribe to job alerts with optional certification uploads.

Body (multipart/form-data):
- `email` (required)
- `firstName`, `lastName`, `city`, `state`
- `sourceTag` - Source of subscription
- `certifications[]` - File uploads (images, PDFs)

## Admin Portal

### Authentication
The admin portal requires two environment variables:
- `ADMIN_PASSWORD` - Password for admin login
- `ADMIN_SESSION_SECRET` - Secret for session encryption

Without these secrets, the server will not start (fail-fast security).

### Admin Pages
- **/admin-login.html** - Secure login page
- **/admin.html** - Dashboard with three tabs:
  - **Subscribers Tab:** View all email subscribers with their certifications and download uploaded files
  - **Job Submissions Tab:** View all user-submitted job posts
  - **Analytics Tab:** View visitor statistics, popular searches, filters, and job clicks

### Admin API Endpoints (Protected)

All admin endpoints require authentication via session cookie.

#### POST /api/admin/login
Login to admin portal.

Body (JSON):
- `password` (required)

#### POST /api/admin/logout
Logout from admin portal.

#### GET /api/admin/check
Check if current session is authenticated.

#### GET /api/admin/subscribers
Get all subscribers with their certifications.

Returns:
- Subscriber info (name, email, location, source)
- Certification files with download capability

#### GET /api/admin/submitted-jobs
Get all user-submitted job posts.

Returns:
- Job details from users who submitted via the post-job form

#### GET /api/admin/download/:certId
Download a specific certification file.

Requires authentication. Files are NOT publicly accessible.

#### GET /api/admin/analytics
Get aggregated analytics statistics.

Requires authentication.

Returns:
- `totalVisitors` - Total unique visitors (unique session IDs)
- `todayVisitors` - Unique visitors today
- `weekVisitors` - Unique visitors this week
- `topSearches` - Most popular search keywords with counts
- `topFilters` - Most used filter combinations with counts
- `topClicks` - Most clicked jobs with title, company, location, and click counts

### Public API Endpoints

#### POST /api/analytics
Track analytics events (public endpoint).

Body (JSON):
- `event_type` (required) - Event type: "page_visit", "search", "filter", or "job_click"
- `event_data` (optional) - JSON object with event-specific data
- `session_id` (required) - Unique session identifier

## Development

### Running the Application
The workflow automatically starts the unified server:
```bash
npm start
```

This runs the Express server on http://0.0.0.0:5000 which serves:
- Frontend (static files from App/ directory)
- API endpoints (/api/jobs, /api/subscribe)

## Data Sources
Jobs aggregated from:
- Amazon DSP (482 jobs)
- Airspace (283 jobs)
- GoPuff (181 jobs)
- Dropoff (78 jobs)
- MedSpeed (74 jobs)
- RedWagon (33 jobs)
- MDS-RX (25 jobs)
- SDS-RX (24 jobs)
- BlueJay Logistics (5 jobs)
- US-Pack (1 job)

## Recent Changes
- **2025-11-03:** Enhanced Filter Change Tracking
  - Added real-time tracking for individual filter selections (state, city, vehicle)
  - Each dropdown change now fires a 'filter_change' event with filter_type and value
  - Created "Individual Filter Selections" section in Analytics dashboard
  - Captures user exploration behavior even before they click search
  - Helps identify popular locations and vehicle types users are interested in

- **2025-11-03:** Custom Analytics System
  - Created analytics_events table in SQLite database with session-based tracking
  - Implemented POST /api/analytics endpoint for tracking page visits, searches, filters, and job clicks
  - Added GET /api/admin/analytics endpoint for fetching aggregated statistics
  - Built Analytics tab in admin dashboard with visitor stats, popular searches, filters, and job clicks
  - Integrated frontend tracking code using sessionStorage for session IDs
  - Session-based de-duplication ensures one page_visit per session
  - Fire-and-forget event tracking to avoid blocking user experience

- **2025-11-03:** Admin Portal
  - Created secure admin portal with session-based authentication
  - Added admin-login.html with password authentication
  - Built admin.html dashboard with three tabs (Subscribers, Job Submissions, and Analytics)
  - Implemented protected API endpoints: /api/admin/subscribers, /api/admin/submitted-jobs, /api/admin/download/:certId
  - Added fail-fast security: server requires ADMIN_PASSWORD and ADMIN_SESSION_SECRET environment variables
  - Removed public access to /uploads directory - files only accessible via authenticated download endpoint
  - Comprehensive debug logging for subscription system (both frontend and backend)
  - Fixed subscription form to use relative URL path instead of hardcoded localhost


- **2025-10-31:** Job Posting Feature
  - Added `submitted_at` column to jobs table for tracking user-submitted jobs
  - Created POST /api/jobs endpoint for job submissions with validation
  - Implemented 24-hour filtering: user-submitted jobs automatically hide after 24 hours (remain in database)
  - Built post-job.html form page with all job fields and success modal preview
  - Added "Post a Job" link to main navigation
  - Scraped jobs (submitted_at = NULL) unaffected by time-based filtering

- **2025-10-31:** Configured for Replit environment
  - Consolidated frontend and backend to run on single Express server (port 5000)
  - Renamed landing.html to index.html for automatic root serving
  - Disabled directory listing in Express static file serving
  - Fixed mobile compatibility by changing API_URL from `http://localhost:3000/api/jobs` to relative path `/api/js`
  - Added cache control headers to prevent stale content
  - Configured deployment for autoscale target
  - Fixed Subscribe button bell icon preservation by targeting `.subscribe-text` span instead of replacing entire button content
  - Improved mobile subscribe modal layout with proper spacing (85vh max-height, 20px margins, adjusted padding) to prevent form from touching screen edges
  - Optimized mobile jobs section layout: hidden "Available Jobs" heading and reduced vertical spacing (32px top padding, 24px header margin) for better space efficiency
  - Reduced mobile hero section padding from 80px/60px to 40px/40px (top/bottom) for more compact filter area

## User Preferences
None documented yet.

## Notes
- The database is pre-populated with 1,186 scraped job listings
- PostHog analytics is configured with project API key
- File uploads are stored in `uploads/certifications/` directory
- Maximum file upload size is 10MB per file
- User-submitted jobs are visible for 24 hours, then automatically hidden (not deleted)
- Job posting flow: Form → Validation → Insert with `submitted_at = NOW()` → Success modal preview
