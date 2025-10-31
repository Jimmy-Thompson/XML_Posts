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
│   └── cities_by_state.json   # Location filter data
├── shared/
│   └── db.js                  # SQLite database connection
├── outputs/
│   └── master_database/
│       └── master_jobs.db     # Job database (SQLite)
├── uploads/
│   └── certifications/        # User certification uploads
├── api-server.js              # Express API server
└── package.json               # Dependencies and scripts
```

### Ports
- **Unified Server:** Port 5000 (Express.js serves both static frontend and API endpoints)

### Database Schema
- **jobs:** Job listings with title, company, location, requirements, benefits, etc. Includes `submitted_at` column to track user-submitted jobs for 24-hour visibility.
- **subscribers:** Email subscriptions for job alerts
- **subscriber_certifications:** Uploaded certification files

## Key Features
- Advanced search across job titles, descriptions, and requirements
- Location filtering by state and city
- Vehicle type filtering (Van, Box Truck, Car, etc.)
- Certification search functionality
- Job alerts subscription with certification upload
- **Job posting form** - Users can submit jobs that appear for 24 hours
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
