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
│   ├── landing.html           # Main frontend interface
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
- **Frontend:** Port 5000 (http-server serving static HTML)
- **Backend API:** Port 3000 (Express.js)

### Database Schema
- **jobs:** Job listings with title, company, location, requirements, benefits, etc.
- **subscribers:** Email subscriptions for job alerts
- **subscriber_certifications:** Uploaded certification files

## Key Features
- Advanced search across job titles, descriptions, and requirements
- Location filtering by state and city
- Vehicle type filtering (Van, Box Truck, Car, etc.)
- Certification search functionality
- Job alerts subscription with certification upload
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

### POST /api/subscribe
Subscribe to job alerts with optional certification uploads.

Body (multipart/form-data):
- `email` (required)
- `firstName`, `lastName`, `city`, `state`
- `sourceTag` - Source of subscription
- `certifications[]` - File uploads (images, PDFs)

## Development

### Running the Application
The workflow automatically starts both servers:
```bash
npm start
```

This runs:
- API server on http://localhost:3000
- Frontend on http://0.0.0.0:5000

### Individual Commands
```bash
npm run api  # Start API server only
npm run dev  # Start frontend only
```

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
- **2025-10-31:** Configured for Replit environment
  - Updated frontend to run on port 5000 with 0.0.0.0 binding
  - Modified API URLs to use dynamic hostname detection
  - Configured workflow to run both frontend and backend concurrently
  - Added CORS support for http-server

## User Preferences
None documented yet.

## Notes
- The database is pre-populated with 1,186 job listings
- PostHog analytics is configured with project API key
- File uploads are stored in `uploads/certifications/` directory
- Maximum file upload size is 10MB per file
