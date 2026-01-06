# GigSafe Job Board

Lean job posting + XML feed service backed by PostgreSQL user submissions.

## What This Does
- Hosts a job posting page at `/post-job.html`
- Accepts job submissions via `POST /api/jobs`
- Renders job detail pages at `/jobs/:id`
- Generates an XML feed at `/user_jobs_feed.xml`

## Quick Start

Prerequisites:
- Node.js 18+
- PostgreSQL database with a `user_submitted_jobs` table

Install dependencies:
```bash
npm install
```

Start the server:
```bash
npm start
```

## Environment
Copy `.env.example` and set:
- `DATABASE_URL`
- Optional XML settings (`XML_*`)

## API

### `POST /api/jobs`
Creates a new user-submitted job in PostgreSQL.

Required fields:
- `job_url`, `title`, `company`, `city`, `state`, `postalcode`, `description`, `pay`

## Scripts
- `npm run export:user-xml` generates `App/user_jobs_feed.xml`
