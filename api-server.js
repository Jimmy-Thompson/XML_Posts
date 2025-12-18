import express from 'express';
import cors from 'cors';
import multer from 'multer';
import session from 'express-session';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { getDb, getUserDb, closeDb } from './shared/db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 5000;

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads', 'certifications');
    fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit per file
  fileFilter: (req, file, cb) => {
    // Allow images and PDFs
    const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only images, PDFs, and Word documents are allowed'));
    }
  }
});

app.use(cors());
app.use(express.json());

// Session management for admin authentication
const sessionSecret = process.env.ADMIN_SESSION_SECRET;
if (!sessionSecret) {
  console.error('FATAL: ADMIN_SESSION_SECRET environment variable is not set.');
  console.error('The admin portal requires a strong session secret for security.');
  console.error('Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Secure cookies in production
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'App', 'index.html'));
});

app.use(express.static('App', {
  index: false,
  dotfiles: 'deny',
  extensions: ['html']
}));

// Middleware to check admin authentication
const requireAdmin = (req, res, next) => {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  res.status(401).json({
    success: false,
    error: 'Unauthorized - Admin access required'
  });
};

function buildFilters(query) {
  const keyword = query.keyword?.trim() || '';
  const state = query.state?.trim() || '';
  const city = query.city?.trim() || '';
  const vehicle = query.vehicle?.trim() || '';
  const certifications = query.certifications?.trim() || '';

  return { keyword, state, city, vehicle, certifications };
}

function buildWhereClause(filters, params) {
  const whereConditions = [];

  // Filter out user-submitted jobs older than 24 hours
  whereConditions.push(`(submitted_at IS NULL OR datetime(submitted_at) > datetime('now', '-24 hours'))`);

  if (filters.keyword) {
    whereConditions.push(`(
      title LIKE ? COLLATE NOCASE OR
      description LIKE ? COLLATE NOCASE OR
      company LIKE ? COLLATE NOCASE OR
      benefits LIKE ? COLLATE NOCASE OR
      schedule_details LIKE ? COLLATE NOCASE OR
      general_requirements LIKE ? COLLATE NOCASE
    )`);
    const pattern = `%${filters.keyword}%`;
    params.push(pattern, pattern, pattern, pattern, pattern, pattern);
  }

  if (filters.state) {
    whereConditions.push('state = ?');
    params.push(filters.state);
  }

  if (filters.city) {
    whereConditions.push('city = ?');
    params.push(filters.city);
  }

  if (filters.vehicle) {
    whereConditions.push('vehicle_requirements LIKE ? COLLATE NOCASE');
    params.push(`%${filters.vehicle}%`);
  }

  if (filters.certifications) {
    const certList = filters.certifications
      .split(',')
      .map(cert => cert.trim())
      .filter(Boolean);

    if (certList.length > 0) {
      const certConditions = certList
        .map(() => 'description LIKE ? COLLATE NOCASE OR benefits LIKE ? COLLATE NOCASE')
        .join(' OR ');
      whereConditions.push(`(${certConditions})`);
      certList.forEach(cert => {
        params.push(`%${cert}%`, `%${cert}%`);
      });
    }
  }

  return `WHERE ${whereConditions.join(' AND ')}`;
}

app.get('/api/jobs', (req, res) => {
  const page = Number.parseInt(req.query.page) || 1;
  const limit = Number.parseInt(req.query.limit) || 20;
  const offset = (page - 1) * limit;

  const filters = buildFilters(req.query);
  const params = [];
  const whereClause = buildWhereClause(filters, params);

  const masterDb = getDb();

  try {
    // Attach user database to enable UNION ALL query across both databases
    const userDbPath = path.join(__dirname, 'outputs', 'user_jobs.db');
    masterDb.exec(`ATTACH DATABASE '${userDbPath}' AS user_db`);

    // Count total jobs from both databases using UNION ALL
    // Filter out hidden jobs from user_db.jobs
    const userWhereClause = whereClause === 'WHERE 1=1' 
      ? 'WHERE hidden = 0' 
      : whereClause + ' AND hidden = 0';
    
    const countQuery = `
      SELECT SUM(cnt) as count FROM (
        SELECT COUNT(*) as cnt FROM jobs ${whereClause}
        UNION ALL
        SELECT COUNT(*) as cnt FROM user_db.jobs ${userWhereClause}
      )
    `;
    const { count: totalJobs } = masterDb.prepare(countQuery).get(...params, ...params);

    // UNION ALL query to get jobs from both databases with pagination
    // Wrap UNION in subquery to properly apply ORDER BY and LIMIT
    // Filter out hidden jobs from user_db.jobs
    const unionQuery = filters.keyword
      ? `
        SELECT * FROM (
          SELECT
            id,
            job_url,
            title,
            company,
            city,
            state,
            address,
            description,
            general_requirements,
            pay,
            benefits,
            vehicle_requirements,
            insurance_requirement,
            schedule_details,
            source_company,
            submitted_at
          FROM user_db.jobs
          ${userWhereClause}
          UNION ALL
          SELECT
            id,
            job_url,
            title,
            company,
            city,
            state,
            address,
            description,
            general_requirements,
            pay,
            benefits,
            vehicle_requirements,
            insurance_requirement,
            schedule_details,
            source_company,
            submitted_at
          FROM jobs
          ${whereClause}
        ) AS combined
        ORDER BY
          CASE WHEN submitted_at IS NOT NULL THEN 0 ELSE 1 END,
          CASE
            WHEN title LIKE ? COLLATE NOCASE THEN 1
            WHEN description LIKE ? COLLATE NOCASE THEN 2
            WHEN schedule_details LIKE ? COLLATE NOCASE THEN 3
            WHEN general_requirements LIKE ? COLLATE NOCASE THEN 4
            ELSE 5
          END,
          submitted_at DESC,
          id DESC
        LIMIT ? OFFSET ?
      `
      : `
        SELECT * FROM (
          SELECT
            id,
            job_url,
            title,
            company,
            city,
            state,
            address,
            description,
            general_requirements,
            pay,
            benefits,
            vehicle_requirements,
            insurance_requirement,
            schedule_details,
            source_company,
            submitted_at
          FROM user_db.jobs
          ${userWhereClause}
          UNION ALL
          SELECT
            id,
            job_url,
            title,
            company,
            city,
            state,
            address,
            description,
            general_requirements,
            pay,
            benefits,
            vehicle_requirements,
            insurance_requirement,
            schedule_details,
            source_company,
            submitted_at
          FROM jobs
          ${whereClause}
        ) AS combined
        ORDER BY
          CASE WHEN submitted_at IS NOT NULL THEN 0 ELSE 1 END,
          submitted_at DESC,
          id DESC
        LIMIT ? OFFSET ?
      `;

    // Build params array for the union query
    const queryParams = filters.keyword
      ? [
          ...params, // WHERE clause for user_db.jobs
          ...params, // WHERE clause for main jobs
          `%${filters.keyword}%`, `%${filters.keyword}%`, `%${filters.keyword}%`, `%${filters.keyword}%`, // ORDER BY relevance scoring
          limit,
          offset
        ]
      : [...params, ...params, limit, offset];

    const jobs = masterDb.prepare(unionQuery).all(...queryParams);

    // Detach user database
    masterDb.exec('DETACH DATABASE user_db');

    res.json({
      success: true,
      data: jobs,
      pagination: {
        page,
        limit,
        totalJobs,
        totalPages: Math.ceil(totalJobs / limit),
        hasMore: offset + jobs.length < totalJobs
      },
      filters
    });
  } catch (error) {
    console.error('Error fetching jobs:', error);
    // Ensure database is detached even on error
    try {
      masterDb.exec('DETACH DATABASE user_db');
    } catch (detachError) {
      // Ignore detach errors
    }
    res.status(500).json({
      success: false,
      error: 'Failed to fetch jobs'
    });
  }
});

app.post('/api/jobs', (req, res) => {
  const {
    job_url,
    title,
    company,
    city,
    state,
    address,
    description,
    general_requirements,
    pay,
    benefits,
    vehicle_requirements,
    insurance_requirement,
    schedule_details
  } = req.body;

  // Validate required fields
  if (!title || !company || !job_url || !city || !state || !description || !pay) {
    return res.status(400).json({
      success: false,
      error: 'Required fields: title, company, job_url, city, state, description, pay'
    });
  }

  // Validate URL format
  try {
    new URL(job_url);
  } catch {
    return res.status(400).json({
      success: false,
      error: 'Invalid job_url format'
    });
  }

  const userDb = getUserDb();

  try {
    const result = userDb.prepare(`
      INSERT INTO jobs (
        job_url,
        title,
        company,
        city,
        state,
        address,
        description,
        general_requirements,
        pay,
        benefits,
        vehicle_requirements,
        insurance_requirement,
        schedule_details,
        source_company,
        submitted_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      RETURNING *
    `).get(
      job_url,
      title.trim(),
      company.trim(),
      city.trim(),
      state.trim().toUpperCase(),
      address?.trim() || null,
      description.trim(),
      general_requirements?.trim() || null,
      pay.trim(),
      benefits?.trim() || null,
      vehicle_requirements?.trim() || null,
      insurance_requirement?.trim() || null,
      schedule_details?.trim() || null,
      company.trim()
    );

    res.json({
      success: true,
      message: 'Job posted successfully',
      data: result
    });
  } catch (error) {
    console.error('Error posting job:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to post job'
    });
  }
});

app.delete('/api/jobs/:id', (req, res) => {
  const jobId = Number.parseInt(req.params.id);

  if (!jobId || isNaN(jobId)) {
    return res.status(400).json({
      success: false,
      error: 'Valid job ID is required'
    });
  }

  const masterDb = getDb();
  const userDb = getUserDb();

  try {
    // Try deleting from user database first
    let result = userDb.prepare('DELETE FROM jobs WHERE id = ?').run(jobId);

    // If not found in user DB, try master DB
    if (result.changes === 0) {
      result = masterDb.prepare('DELETE FROM jobs WHERE id = ?').run(jobId);
    }

    if (result.changes === 0) {
      return res.status(404).json({
        success: false,
        error: 'Job not found'
      });
    }

    res.json({
      success: true,
      message: 'Job deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting job:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete job'
    });
  }
});

// Protected: Toggle hidden status for user-submitted job
app.patch('/api/admin/jobs/:id/hide', requireAdmin, (req, res) => {
  const jobId = Number.parseInt(req.params.id);

  if (!jobId || isNaN(jobId)) {
    return res.status(400).json({
      success: false,
      error: 'Valid job ID is required'
    });
  }

  const userDb = getUserDb();

  try {
    // Get current job to check if it exists and get current hidden status
    const job = userDb.prepare('SELECT id, hidden FROM jobs WHERE id = ?').get(jobId);

    if (!job) {
      return res.status(404).json({
        success: false,
        error: 'User-submitted job not found'
      });
    }

    // Toggle hidden status
    const newHiddenStatus = job.hidden ? 0 : 1;
    const result = userDb.prepare('UPDATE jobs SET hidden = ? WHERE id = ?').run(newHiddenStatus, jobId);

    if (result.changes === 0) {
      return res.status(500).json({
        success: false,
        error: 'Failed to update job visibility'
      });
    }

    res.json({
      success: true,
      message: newHiddenStatus ? 'Job hidden successfully' : 'Job unhidden successfully',
      hidden: newHiddenStatus === 1
    });
  } catch (error) {
    console.error('Error toggling job visibility:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to toggle job visibility'
    });
  }
});

app.post('/api/subscribe', upload.array('certifications', 10), (req, res) => {
  console.log('======================================');
  console.log('SUBSCRIBE REQUEST RECEIVED');
  console.log('======================================');
  console.log('Request body:', req.body);
  console.log('Files received:', req.files ? req.files.length : 0);
  if (req.files) {
    req.files.forEach((f, i) => console.log(`  File ${i}:`, f.originalname, f.size, 'bytes'));
  }

  const {
    email,
    firstName,
    lastName,
    city,
    state,
    sourceTag
  } = req.body ?? {};

  console.log('Extracted fields:', { email, firstName, lastName, city, state, sourceTag });

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    console.log('ERROR: Invalid email');
    return res.status(400).json({
      success: false,
      error: 'Valid email address is required'
    });
  }

  const sanitizedEmail = email.trim().toLowerCase();
  const tag = typeof sourceTag === 'string' ? sourceTag.trim() || null : null;
  const first = typeof firstName === 'string' && firstName.trim() ? firstName.trim() : null;
  const last = typeof lastName === 'string' && lastName.trim() ? lastName.trim() : null;
  const cityValue = typeof city === 'string' && city.trim() ? city.trim() : null;
  const stateValue = typeof state === 'string' && state.trim() ? state.trim() : null;

  console.log('Sanitized values:', { sanitizedEmail, first, last, cityValue, stateValue, tag });

  const db = getDb();

  try {
    console.log('Starting database transaction...');
    // Use a transaction to ensure both subscriber and certifications are saved together
    db.transaction(() => {
      console.log('Inserting subscriber into database...');
      // Insert or update subscriber
      const result = db.prepare(`
        INSERT INTO subscribers (email, first_name, last_name, city, state, source_tag)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
          first_name = COALESCE(excluded.first_name, subscribers.first_name),
          last_name = COALESCE(excluded.last_name, subscribers.last_name),
          city = COALESCE(excluded.city, subscribers.city),
          state = COALESCE(excluded.state, subscribers.state),
          source_tag = COALESCE(excluded.source_tag, subscribers.source_tag)
        RETURNING id
      `).get(sanitizedEmail, first, last, cityValue, stateValue, tag);

      // Get the subscriber ID from RETURNING clause
      const subscriberId = result.id;
      console.log('Subscriber saved with ID:', subscriberId);

      // Save certification files if any were uploaded
      if (req.files && req.files.length > 0) {
        console.log(`Saving ${req.files.length} certification files...`);
        const insertCert = db.prepare(`
          INSERT INTO subscriber_certifications
          (subscriber_id, certification_type, file_name, file_path, file_size, mime_type)
          VALUES (?, ?, ?, ?, ?, ?)
        `);

        req.files.forEach((file, index) => {
          // Get certification type from form data
          const certType = req.body[`cert_type_${index}`] || 'Unknown';
          const relativePath = path.join('uploads', 'certifications', file.filename);

          console.log(`  Cert ${index}: ${certType} - ${file.originalname}`);
          insertCert.run(
            subscriberId,
            certType,
            file.originalname,
            relativePath,
            file.size,
            file.mimetype
          );
        });
        console.log('All certifications saved successfully');
      } else {
        console.log('No certification files to save');
      }
    })();

    console.log('Transaction committed successfully');
    console.log('======================================');
    res.json({
      success: true,
      message: 'Subscribed successfully',
      filesUploaded: req.files ? req.files.length : 0
    });
  } catch (error) {
    console.error('======================================');
    console.error('ERROR storing subscriber:', error);
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    console.error('======================================');

    // Clean up uploaded files if there was an error
    if (req.files) {
      req.files.forEach(file => {
        try {
          fs.unlinkSync(file.path);
        } catch (err) {
          console.error('Error deleting file:', err);
        }
      });
    }

    res.status(500).json({
      success: false,
      error: 'Failed to save subscription'
    });
  }
});

// Analytics endpoint (public) - Track events
app.post('/api/analytics', (req, res) => {
  const { event_type, event_data, session_id } = req.body;

  if (!event_type || !session_id) {
    return res.status(400).json({
      success: false,
      error: 'event_type and session_id are required'
    });
  }

  const db = getDb();

  try {
    // Optional: Hash IP for privacy (simple hash)
    const ipHash = req.ip ? 
      crypto.createHash('sha256').update(req.ip).digest('hex').substring(0, 16) : 
      null;

    db.prepare(`
      INSERT INTO analytics_events (event_type, event_data, session_id, ip_hash)
      VALUES (?, ?, ?, ?)
    `).run(
      event_type,
      event_data ? JSON.stringify(event_data) : null,
      session_id,
      ipHash
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Error tracking analytics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to track event'
    });
  }
});

// Admin login endpoint
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminPassword) {
    console.error('ADMIN_PASSWORD not configured');
    return res.status(503).json({
      success: false,
      error: 'Admin portal not configured. Please contact administrator.'
    });
  }

  if (password === adminPassword) {
    req.session.isAdmin = true;
    res.json({
      success: true,
      message: 'Login successful'
    });
  } else {
    res.status(401).json({
      success: false,
      error: 'Invalid password'
    });
  }
});

// Admin logout endpoint
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: 'Failed to logout'
      });
    }
    res.json({
      success: true,
      message: 'Logged out successfully'
    });
  });
});

// Check admin authentication status
app.get('/api/admin/check', (req, res) => {
  res.json({
    isAuthenticated: !!(req.session && req.session.isAdmin)
  });
});

// Protected: Get all subscribers and their certifications
app.get('/api/admin/subscribers', requireAdmin, (req, res) => {
  const db = getDb();

  try {
    const subscribers = db.prepare(`
      SELECT id, email, first_name, last_name, city, state, source_tag, created_at
      FROM subscribers
      ORDER BY created_at DESC
    `).all();

    // Get certifications for each subscriber
    const subscribersWithCerts = subscribers.map(sub => {
      const certs = db.prepare(`
        SELECT id, certification_type, file_name, file_path, file_size, mime_type, uploaded_at
        FROM subscriber_certifications
        WHERE subscriber_id = ?
      `).all(sub.id);

      return {
        ...sub,
        certifications: certs
      };
    });

    res.json({
      success: true,
      count: subscribers.length,
      subscribers: subscribersWithCerts
    });
  } catch (error) {
    console.error('Error fetching subscribers:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch subscribers'
    });
  }
});

// Protected: Get all submitted jobs
app.get('/api/admin/submitted-jobs', requireAdmin, (req, res) => {
  const userDb = getUserDb();

  try {
    const jobs = userDb.prepare(`
      SELECT *
      FROM jobs
      ORDER BY submitted_at DESC
    `).all();

    res.json({
      success: true,
      count: jobs.length,
      jobs: jobs
    });
  } catch (error) {
    console.error('Error fetching submitted jobs:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch submitted jobs'
    });
  }
});

// Protected: Get analytics data
app.get('/api/admin/analytics', requireAdmin, (req, res) => {
  const db = getDb();
  const timeRange = req.query.timeRange || 'all';

  try {
    // Helper function to get date filter SQL based on time range
    const getDateFilter = (range) => {
      switch (range) {
        case 'today':
          return "AND DATE(created_at) = DATE('now')";
        case 'yesterday':
          return "AND DATE(created_at) = DATE('now', '-1 day')";
        case '7days':
          return "AND created_at >= datetime('now', '-7 days')";
        case '14days':
          return "AND created_at >= datetime('now', '-14 days')";
        case 'all':
        default:
          return '';
      }
    };

    const dateFilter = getDateFilter(timeRange);

    // Unique visitors (unique session IDs)
    const uniqueVisitorsTotal = db.prepare(`
      SELECT COUNT(DISTINCT session_id) as count
      FROM analytics_events
      WHERE event_type = 'page_visit'
    `).get();

    const uniqueVisitorsToday = db.prepare(`
      SELECT COUNT(DISTINCT session_id) as count
      FROM analytics_events
      WHERE event_type = 'page_visit'
      AND DATE(created_at) = DATE('now')
    `).get();

    const uniqueVisitorsWeek = db.prepare(`
      SELECT COUNT(DISTINCT session_id) as count
      FROM analytics_events
      WHERE event_type = 'page_visit'
      AND created_at >= datetime('now', '-7 days')
    `).get();

    // Popular searches
    const popularSearches = db.prepare(`
      SELECT 
        json_extract(event_data, '$.keyword') as search_term,
        COUNT(*) as count
      FROM analytics_events
      WHERE event_type = 'search'
      AND json_extract(event_data, '$.keyword') != ''
      GROUP BY search_term
      ORDER BY count DESC
      LIMIT 20
    `).all();

    // Popular filters
    const popularFilters = db.prepare(`
      SELECT 
        json_extract(event_data, '$.state') as state,
        json_extract(event_data, '$.city') as city,
        json_extract(event_data, '$.vehicle') as vehicle,
        COUNT(*) as count
      FROM analytics_events
      WHERE event_type = 'filter'
      GROUP BY state, city, vehicle
      ORDER BY count DESC
      LIMIT 20
    `).all();

    // Individual filter selections (filter_change events)
    const filterSelections = db.prepare(`
      SELECT 
        json_extract(event_data, '$.filter_type') as filter_type,
        json_extract(event_data, '$.value') as filter_value,
        COUNT(*) as count
      FROM analytics_events
      WHERE event_type = 'filter_change'
      AND json_extract(event_data, '$.value') != 'Any'
      GROUP BY filter_type, filter_value
      ORDER BY count DESC
      LIMIT 30
    `).all();

    // Most clicked jobs
    const mostClickedJobs = db.prepare(`
      SELECT 
        json_extract(event_data, '$.title') as job_title,
        json_extract(event_data, '$.company') as company,
        json_extract(event_data, '$.location') as location,
        COUNT(*) as clicks
      FROM analytics_events
      WHERE event_type = 'job_click'
      GROUP BY job_title, company, location
      ORDER BY clicks DESC
      LIMIT 20
    `).all();

    // Time-series data for clicks over time (total clicks per day)
    const clicksOverTime = db.prepare(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as clicks
      FROM analytics_events
      WHERE event_type = 'job_click'
      ${dateFilter}
      GROUP BY DATE(created_at)
      ORDER BY date ASC
    `).all();

    // Get top 5 most clicked jobs for the selected time range
    const top5JobsForRange = db.prepare(`
      SELECT 
        json_extract(event_data, '$.title') as job_title,
        json_extract(event_data, '$.company') as company,
        COUNT(*) as clicks
      FROM analytics_events
      WHERE event_type = 'job_click'
      ${dateFilter}
      GROUP BY job_title, company
      ORDER BY clicks DESC
      LIMIT 5
    `).all();

    // Time-series data for top 5 jobs (clicks per day for each job)
    const top5JobsOverTime = [];
    for (const job of top5JobsForRange) {
      const jobClicksOverTime = db.prepare(`
        SELECT 
          DATE(created_at) as date,
          COUNT(*) as clicks
        FROM analytics_events
        WHERE event_type = 'job_click'
        AND json_extract(event_data, '$.title') = ?
        AND json_extract(event_data, '$.company') = ?
        ${dateFilter}
        GROUP BY DATE(created_at)
        ORDER BY date ASC
      `).all(job.job_title, job.company);

      top5JobsOverTime.push({
        title: job.job_title,
        company: job.company,
        data: jobClicksOverTime
      });
    }

    res.json({
      success: true,
      stats: {
        totalVisitors: uniqueVisitorsTotal.count || 0,
        todayVisitors: uniqueVisitorsToday.count || 0,
        weekVisitors: uniqueVisitorsWeek.count || 0,
        topSearches: popularSearches.map(s => ({
          keyword: s.search_term,
          count: s.count
        })),
        topFilters: popularFilters.map(f => {
          const parts = [];
          if (f.state) parts.push(`State: ${f.state}`);
          if (f.city) parts.push(`City: ${f.city}`);
          if (f.vehicle && f.vehicle !== 'Any') parts.push(`Vehicle: ${f.vehicle}`);
          return {
            filter: parts.join(', ') || 'Various filters',
            count: f.count
          };
        }),
        topFilterSelections: filterSelections.map(fs => ({
          type: fs.filter_type,
          value: fs.filter_value,
          count: fs.count
        })),
        topClicks: mostClickedJobs.map(j => ({
          title: j.job_title,
          company: j.company,
          location: j.location || 'Location not tracked',
          count: j.clicks
        })),
        clicksOverTime: clicksOverTime,
        top5JobsOverTime: top5JobsOverTime
      }
    });
  } catch (error) {
    console.error('Error fetching analytics:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch analytics'
    });
  }
});

// Protected: Download certification file
app.get('/api/admin/download/:certId', requireAdmin, (req, res) => {
  const { certId } = req.params;
  const db = getDb();

  try {
    const cert = db.prepare(`
      SELECT file_path, file_name, mime_type
      FROM subscriber_certifications
      WHERE id = ?
    `).get(certId);

    if (!cert) {
      return res.status(404).json({
        success: false,
        error: 'Certification file not found'
      });
    }

    const filePath = path.join(__dirname, cert.file_path);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        error: 'File not found on server'
      });
    }

    res.setHeader('Content-Disposition', `attachment; filename="${cert.file_name}"`);
    res.setHeader('Content-Type', cert.mime_type);
    res.sendFile(filePath);
  } catch (error) {
    console.error('Error downloading file:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to download file'
    });
  }
});

// Initialize user jobs database with schema
function initializeUserJobsDb() {
  const userDb = getUserDb();
  
  // Create jobs table if it doesn't exist
  userDb.exec(`
    CREATE TABLE IF NOT EXISTS jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_url TEXT NOT NULL,
      title TEXT NOT NULL,
      company TEXT NOT NULL,
      city TEXT NOT NULL,
      state TEXT NOT NULL,
      address TEXT,
      description TEXT NOT NULL,
      general_requirements TEXT,
      pay TEXT NOT NULL,
      benefits TEXT,
      vehicle_requirements TEXT,
      insurance_requirement TEXT,
      schedule_details TEXT,
      source_company TEXT,
      submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      hidden INTEGER DEFAULT 0
    )
  `);
  
  // Add hidden column if it doesn't exist (migration for existing databases)
  try {
    userDb.exec(`ALTER TABLE jobs ADD COLUMN hidden INTEGER DEFAULT 0`);
    console.log('Added hidden column to user jobs table');
  } catch (error) {
    // Column already exists, ignore error
  }
  
  console.log('User jobs database initialized');
}

// Initialize databases on startup
initializeUserJobsDb();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`API server running on http://0.0.0.0:${PORT}`);
});

process.on('SIGINT', () => {
  closeDb();
  process.exit(0);
});
