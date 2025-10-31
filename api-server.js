import express from 'express';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { getDb, closeDb } from './shared/db.js';

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

  const db = getDb();

  try {
    const countQuery = `SELECT COUNT(*) as count FROM jobs ${whereClause}`;
    const { count: totalJobs } = db.prepare(countQuery).get(...params);

    const orderClause = filters.keyword
      ? `ORDER BY
          CASE
            WHEN title LIKE ? COLLATE NOCASE THEN 1
            WHEN description LIKE ? COLLATE NOCASE THEN 2
            WHEN schedule_details LIKE ? COLLATE NOCASE THEN 3
            WHEN general_requirements LIKE ? COLLATE NOCASE THEN 4
            ELSE 5
          END,
          id DESC`
      : 'ORDER BY id DESC';

    const jobsQuery = `
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
        source_company
      FROM jobs
      ${whereClause}
      ${orderClause}
      LIMIT ? OFFSET ?
    `;

    const jobsParams = filters.keyword
      ? [...params, `%${filters.keyword}%`, `%${filters.keyword}%`, `%${filters.keyword}%`, `%${filters.keyword}%`, limit, offset]
      : [...params, limit, offset];

    const jobs = db.prepare(jobsQuery).all(...jobsParams);

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

  const db = getDb();

  try {
    const result = db.prepare(`
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

app.post('/api/subscribe', upload.array('certifications', 10), (req, res) => {
  const {
    email,
    firstName,
    lastName,
    city,
    state,
    sourceTag
  } = req.body ?? {};

  if (!email || typeof email !== 'string' || !email.includes('@')) {
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

  const db = getDb();

  try {
    // Use a transaction to ensure both subscriber and certifications are saved together
    db.transaction(() => {
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

      // Save certification files if any were uploaded
      if (req.files && req.files.length > 0) {
        const insertCert = db.prepare(`
          INSERT INTO subscriber_certifications
          (subscriber_id, certification_type, file_name, file_path, file_size, mime_type)
          VALUES (?, ?, ?, ?, ?, ?)
        `);

        req.files.forEach((file, index) => {
          // Get certification type from form data
          const certType = req.body[`cert_type_${index}`] || 'Unknown';
          const relativePath = path.join('uploads', 'certifications', file.filename);

          insertCert.run(
            subscriberId,
            certType,
            file.originalname,
            relativePath,
            file.size,
            file.mimetype
          );
        });
      }
    })();

    res.json({
      success: true,
      message: 'Subscribed successfully',
      filesUploaded: req.files ? req.files.length : 0
    });
  } catch (error) {
    console.error('Error storing subscriber:', error);

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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`API server running on http://0.0.0.0:${PORT}`);
});

process.on('SIGINT', () => {
  closeDb();
  process.exit(0);
});
