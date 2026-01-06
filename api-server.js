import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';
import { Client } from 'pg';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '.env'), override: true });
if (!process.env.DATABASE_URL) {
  console.warn('[config] DATABASE_URL is not set. Check .env location and contents.');
}

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 5000;

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const XML_EXPORT_INTERVAL_MS = Number(process.env.XML_EXPORT_INTERVAL_MS ?? 15 * 60 * 1000);
let xmlExportInProgress = false;
let xmlExportTimer = null;

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDateShort(value) {
  const date = value ? new Date(value) : new Date();
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const dd = String(date.getDate()).padStart(2, '0');
  const yy = String(date.getFullYear()).slice(-2);
  return `${mm}/${dd}/${yy}`;
}

function runXmlExport(reason) {
  if (!process.env.DATABASE_URL) return;
  if (xmlExportInProgress) {
    console.log(`[xml-export] Skip (${reason}) - already running`);
    return;
  }
  const scriptPath = path.join(__dirname, 'scripts', 'export_user_jobs_xml.js');
  xmlExportInProgress = true;
  const child = spawn(process.execPath, [scriptPath], {
    env: { ...process.env, DB_URL: process.env.DATABASE_URL },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', d => console.log(`[xml-export] ${d.toString().trim()}`));
  child.stderr.on('data', d => console.error(`[xml-export] ${d.toString().trim()}`));
  child.on('close', code => {
    xmlExportInProgress = false;
    if (code !== 0) console.error(`[xml-export] failed with code ${code}`);
  });
}

function scheduleXmlExport() {
  if (!process.env.DATABASE_URL) return;
  runXmlExport('startup');
  xmlExportTimer = setInterval(() => runXmlExport('interval'), XML_EXPORT_INTERVAL_MS);
}

function createPgClient() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    throw new Error('DATABASE_URL is required.');
  }
  const useSSL = !dbUrl.includes('localhost') && !dbUrl.includes('127.0.0.1') && !dbUrl.includes('helium');
  return new Client({
    connectionString: dbUrl,
    ssl: useSSL ? { rejectUnauthorized: false } : false
  });
}

async function fetchUserJobFromPostgres(jobId) {
  if (!process.env.DATABASE_URL) return null;
  const client = createPgClient();
  try {
    await client.connect();
    const result = await client.query(
      `SELECT
        id, title, company, city, state, postalcode, address, description, pay,
        general_requirements, benefits, vehicle_requirements, insurance_requirement,
        certifications_required, schedule_details, submitted_at, job_url
       FROM user_submitted_jobs
       WHERE id = $1
         AND hidden = false
       LIMIT 1`,
      [jobId]
    );
    return result.rows[0] ?? null;
  } finally {
    try { await client.end(); } catch (err) {}
  }
}

function renderJobDetailPage(job) {
  const locationParts = [job.address, job.city, job.state, job.postalcode].filter(Boolean);
  const locationText = locationParts.length ? locationParts.join(', ') : 'Location not specified';
  const sanitizedDescription = job.description ? DOMPurify.sanitize(job.description) : '';
  const sanitizedRequirements = job.general_requirements ? DOMPurify.sanitize(job.general_requirements) : '';
  const sanitizedBenefits = job.benefits ? DOMPurify.sanitize(job.benefits) : '';
  const sanitizedSchedule = job.schedule_details ? DOMPurify.sanitize(job.schedule_details) : '';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(job.title)} - GigSafe Job Board</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet" />
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Manrope', sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; padding: 20px; }
    .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 32px; }
    h1 { font-size: 1.8rem; font-weight: 700; color: #1a1a1a; margin-bottom: 8px; }
    .company { font-size: 1.1rem; color: #666; margin-bottom: 16px; }
    .meta { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; color: #888; font-size: 0.9rem; }
    .meta-item { display: flex; align-items: center; gap: 6px; }
    .section { margin-bottom: 24px; }
    .section-title { font-size: 1rem; font-weight: 600; color: #333; margin-bottom: 8px; border-bottom: 2px solid #f0f0f0; padding-bottom: 4px; }
    .section-content { color: #555; }
    .pay { font-size: 1.2rem; font-weight: 600; color: #22c55e; }
    .badge { display: inline-block; padding: 4px 10px; border-radius: 16px; font-size: 0.8rem; font-weight: 500; background: #e5e7eb; color: #374151; margin-right: 6px; margin-bottom: 6px; }
    .badge-cert { background: #fef3c7; color: #92400e; }
    .back-link { display: inline-block; margin-bottom: 20px; color: #3b82f6; text-decoration: none; font-weight: 500; }
    .back-link:hover { text-decoration: underline; }
    .apply-btn { display: inline-block; background: #22c55e; color: white; padding: 14px 32px; border-radius: 8px; font-size: 1.1rem; font-weight: 600; text-decoration: none; margin: 24px 0; transition: background 0.2s; }
    .apply-btn:hover { background: #16a34a; }
  </style>
</head>
<body>
  <div class="container">
    <a href="/post-job.html" class="back-link">&larr; Back to Post a Job</a>
    <h1>${escapeHtml(job.title)}</h1>
    <p class="company">${escapeHtml(job.company)}</p>
    ${job.job_url ? `<a href="${escapeHtml(job.job_url)}" target="_blank" rel="noopener noreferrer" class="apply-btn">Apply Now</a>` : ''}
    <div class="meta">
      <span class="meta-item">&#128205; ${escapeHtml(locationText)}</span>
      <span class="meta-item">&#128197; Posted ${escapeHtml(formatDateShort(job.submitted_at))}</span>
    </div>
    ${job.pay ? `<div class="section"><span class="pay">${escapeHtml(job.pay)}</span></div>` : ''}
    ${sanitizedDescription ? `<div class="section"><div class="section-title">Description</div><div class="section-content">${sanitizedDescription}</div></div>` : ''}
    ${sanitizedRequirements ? `<div class="section"><div class="section-title">Requirements</div><div class="section-content">${sanitizedRequirements}</div></div>` : ''}
    ${sanitizedBenefits ? `<div class="section"><div class="section-title">Benefits</div><div class="section-content">${sanitizedBenefits}</div></div>` : ''}
    ${job.vehicle_requirements ? `<div class="section"><div class="section-title">Vehicle Requirements</div><div class="section-content"><span class="badge">${escapeHtml(job.vehicle_requirements)}</span></div></div>` : ''}
    ${job.certifications_required ? `<div class="section"><div class="section-title">Certifications Required</div><div class="section-content">${job.certifications_required.split(',').map(c => `<span class="badge badge-cert">${escapeHtml(c.trim())}</span>`).join('')}</div></div>` : ''}
    ${sanitizedSchedule ? `<div class="section"><div class="section-title">Schedule</div><div class="section-content">${sanitizedSchedule}</div></div>` : ''}
  </div>
</body>
</html>`;
}

function sanitizeText(text, maxLength = 10000) {
  if (!text || typeof text !== 'string') return text;
  const trimmed = text.trim().substring(0, maxLength);
  return DOMPurify.sanitize(trimmed, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: []
  });
}

function sanitizeHTML(html, maxLength = 50000) {
  if (!html || typeof html !== 'string') return html;
  const trimmed = html.trim().substring(0, maxLength);
  return DOMPurify.sanitize(trimmed, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'p', 'br', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: []
  });
}

// Security headers for inline styles and external font/CDN assets used by the UI.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://fonts.googleapis.com',
        'https://cdn.jsdelivr.net'
      ],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://cdn.jsdelivr.net'
      ],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}));

app.use(express.json({ limit: '1mb' }));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { success: false, error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const jobPostingLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { success: false, error: 'Too many job postings, please try again later.' },
  skipSuccessfulRequests: false
});

app.use(generalLimiter);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'App', 'post-job.html'));
});

app.get('/user_jobs_feed.xml', (req, res) => {
  const xmlPath = path.join(__dirname, 'App', 'user_jobs_feed.xml');
  if (fs.existsSync(xmlPath)) {
    res.setHeader('Content-Type', 'application/xml');
    res.sendFile(xmlPath);
  } else {
    res.status(404).send('XML feed not yet generated');
  }
});

app.use(express.static('App', {
  index: false,
  dotfiles: 'deny',
  extensions: ['html']
}));

app.get('/jobs/:id', async (req, res) => {
  const jobId = Number.parseInt(req.params.id);
  if (!jobId || Number.isNaN(jobId)) {
    return res.status(404).send('Job not found');
  }
  try {
    const job = await fetchUserJobFromPostgres(jobId);
    if (!job) return res.status(404).send('Job not found');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(renderJobDetailPage(job));
  } catch (err) {
    console.error('[job-detail] Error loading job:', err.message);
    res.status(500).send('Failed to load job');
  }
});

app.post('/api/jobs', jobPostingLimiter, async (req, res) => {
  if (!process.env.DATABASE_URL) {
    console.warn('[api/jobs] DATABASE_URL missing at request time');
    return res.status(500).json({
      success: false,
      error: 'DATABASE_URL is not configured'
    });
  }

  const {
    job_url,
    title,
    company,
    city,
    state,
    postalcode,
    address,
    description,
    general_requirements,
    pay,
    benefits,
    vehicle_requirements,
    insurance_requirement,
    certifications_required,
    schedule_details
  } = req.body;

  if (!title || !company || !job_url || !city || !state || !description || !pay || !postalcode) {
    return res.status(400).json({
      success: false,
      error: 'Required fields: title, company, job_url, city, state, postalcode, description, pay'
    });
  }

  let validatedUrl;
  try {
    const urlObj = new URL(job_url);
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      throw new Error('Invalid protocol');
    }
    validatedUrl = urlObj.toString();
  } catch {
    return res.status(400).json({
      success: false,
      error: 'Invalid job_url format. Must be a valid HTTP or HTTPS URL.'
    });
  }

  const sanitizedTitle = sanitizeText(title, 200);
  const sanitizedCompany = sanitizeText(company, 200);
  const sanitizedCity = sanitizeText(city, 100);
  const sanitizedState = sanitizeText(state, 2).toUpperCase();
  const sanitizedPostalcode = sanitizeText(postalcode, 10);
  const sanitizedAddress = address ? sanitizeText(address, 300) : null;
  const sanitizedDescription = sanitizeHTML(description, 10000);
  const sanitizedRequirements = general_requirements ? sanitizeHTML(general_requirements, 5000) : null;
  const sanitizedPay = sanitizeText(pay, 200);
  const sanitizedBenefits = benefits ? sanitizeHTML(benefits, 5000) : null;
  const sanitizedVehicle = vehicle_requirements ? sanitizeText(vehicle_requirements, 200) : null;
  const sanitizedInsurance = insurance_requirement ? sanitizeText(insurance_requirement, 200) : null;
  const sanitizedCerts = certifications_required ? sanitizeText(certifications_required, 500) : null;
  const sanitizedSchedule = schedule_details ? sanitizeHTML(schedule_details, 2000) : null;

  const client = createPgClient();

  try {
    await client.connect();
    const result = await client.query(`
      INSERT INTO user_submitted_jobs (
        job_url,
        title,
        company,
        city,
        state,
        postalcode,
        address,
        description,
        general_requirements,
        pay,
        benefits,
        vehicle_requirements,
        insurance_requirement,
        certifications_required,
        schedule_details,
        source_company,
        submitted_at,
        hidden
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW(), false)
      RETURNING *
    `, [
      validatedUrl,
      sanitizedTitle,
      sanitizedCompany,
      sanitizedCity,
      sanitizedState,
      sanitizedPostalcode,
      sanitizedAddress,
      sanitizedDescription,
      sanitizedRequirements,
      sanitizedPay,
      sanitizedBenefits,
      sanitizedVehicle,
      sanitizedInsurance,
      sanitizedCerts,
      sanitizedSchedule,
      sanitizedCompany
    ]);

    const job = result.rows[0];
    runXmlExport('job_posted');

    res.json({
      success: true,
      message: 'Job posted successfully',
      data: job
    });
  } catch (error) {
    console.error('Error posting job:', error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to post job'
    });
  } finally {
    await client.end();
  }
});

scheduleXmlExport();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`API server running on http://0.0.0.0:${PORT}`);
});

process.on('SIGINT', () => {
  if (xmlExportTimer) clearInterval(xmlExportTimer);
  process.exit(0);
});

process.on('SIGTERM', () => {
  if (xmlExportTimer) clearInterval(xmlExportTimer);
  process.exit(0);
});
