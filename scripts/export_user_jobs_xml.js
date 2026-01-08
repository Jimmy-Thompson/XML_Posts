import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { Client } from 'pg';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env file from parent directory
dotenv.config({ path: path.join(__dirname, '..', '.env'), override: true });

const config = {
  publisher: process.env.XML_PUBLISHER ?? 'GigSafe',
  publisherUrl: process.env.XML_PUBLISHER_URL ?? 'https://www.gigsafe.com/',
  notificationEmail: process.env.XML_NOTIFICATION_EMAIL ?? 'jimmy@gigsafe.com',
  country: process.env.XML_DEFAULT_COUNTRY ?? 'US',
  jobType: process.env.XML_DEFAULT_JOBTYPE ?? 'Pt. Time/Contract',
  category: process.env.XML_DEFAULT_CATEGORY ?? 'Logistics',
  baseUrl: process.env.XML_BASE_URL ?? 'https://gigsafe-jobboard.replit.app',
  outputPath: process.env.XML_OUTPUT_PATH ?? path.join(__dirname, '..', 'App', 'user_jobs_feed.xml')
};

function escapeXml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function cdata(value) {
  const text = value === null || value === undefined ? '' : String(value);
  return `<![CDATA[${text.replace(/]]>/g, ']]]]><![CDATA[>')}]]>`;
}

function formatDate(value) {
  const date = value ? new Date(value) : new Date();
  return date.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, '');
}

function warnIfDefault(label, value, fallback) {
  if (value === fallback) {
    console.warn(`Warning: ${label} is using the default '${fallback}'. Set ${label} to override.`);
  }
}

warnIfDefault('XML_PUBLISHER', config.publisher, 'GigSafe');
warnIfDefault('XML_PUBLISHER_URL', config.publisherUrl, 'https://www.gigsafe.com/');
warnIfDefault('XML_NOTIFICATION_EMAIL', config.notificationEmail, 'jimmy@gigsafe.com');
warnIfDefault('XML_DEFAULT_COUNTRY', config.country, 'US');
warnIfDefault('XML_DEFAULT_JOBTYPE', config.jobType, 'Pt. Time/Contract');
warnIfDefault('XML_DEFAULT_CATEGORY', config.category, 'Logistics');
warnIfDefault('XML_BASE_URL', config.baseUrl, 'https://gigsafe-jobboard.replit.app');

async function main() {
  const dbUrl = process.env.DB_URL || process.env.DATABASE_URL;
  if (!dbUrl) {
    throw new Error('DB_URL or DATABASE_URL is required to export the XML feed.');
  }

  const client = new Client({ connectionString: dbUrl });
  await client.connect();

  const result = await client.query(`
    SELECT
      id,
      title,
      submitted_at,
      company,
      address,
      city,
      state,
      description,
      postalcode
    FROM user_submitted_jobs
    WHERE hidden = false
    ORDER BY submitted_at DESC, id DESC
  `);

  const lines = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push('<source>');
  lines.push(`  <publisher>${escapeXml(config.publisher)}</publisher>`);
  lines.push(`  <publisherurl>${escapeXml(config.publisherUrl)}</publisherurl>`);

  let included = 0;
  for (const job of result.rows) {
    const missing = [];
    if (!job.title) missing.push('title');
    if (!job.submitted_at) missing.push('submitted_at');
    if (!config.baseUrl) missing.push('base_url');
    if (!job.company) missing.push('company');
    if (!job.city) missing.push('city');
    if (!job.state) missing.push('state');
    if (!job.postalcode) missing.push('postalcode');
    if (!job.description) missing.push('description');

    if (missing.length > 0) {
      console.warn(`Skipping job ${job.id}: missing ${missing.join(', ')}`);
      continue;
    }

    const jobUrl = `${config.baseUrl.replace(/\/$/, '')}/jobs/${job.id}`;
    lines.push('  <job>');
    lines.push(`    <title>${cdata(job.title)}</title>`);
    lines.push(`    <date>${cdata(formatDate(job.submitted_at))}</date>`);
    lines.push(`    <referencenumber>${cdata(job.id)}</referencenumber>`);
    lines.push(`    <url>${cdata(jobUrl)}</url>`);
    lines.push(`    <company>${cdata('GigSafe')}</company>`);
    lines.push(`    <priority>${cdata('No')}</priority>`);
    lines.push(`    <address>${cdata(job.address ?? '')}</address>`);
    lines.push(`    <city>${cdata(job.city)}</city>`);
    lines.push(`    <state>${cdata(job.state)}</state>`);
    lines.push(`    <country>${cdata(config.country)}</country>`);
    lines.push(`    <postalcode>${cdata(job.postalcode)}</postalcode>`);
    lines.push(`    <description>${cdata(job.description)}</description>`);
    lines.push(`    <jobtype>${cdata(config.jobType)}</jobtype>`);
    lines.push(`    <salary>${cdata('')}</salary>`);
    lines.push(`    <category>${cdata(config.category)}</category>`);
    lines.push(`    <branch>${cdata('')}</branch>`);
    lines.push(`    <owner>${cdata('')}</owner>`);
    lines.push(`    <statewide>${cdata('')}</statewide>`);
    lines.push(`    <nationwide>${cdata('No')}</nationwide>`);
    lines.push(`    <notification>${cdata(config.notificationEmail)}</notification>`);
    lines.push('  </job>');
    included += 1;
  }

  lines.push('</source>');

  fs.mkdirSync(path.dirname(config.outputPath), { recursive: true });
  fs.writeFileSync(config.outputPath, lines.join('\n'), 'utf-8');

  console.log(`Wrote ${included} jobs to ${config.outputPath}`);
  await client.end();
}

main().catch((error) => {
  console.error('XML export failed:', error);
  process.exit(1);
});
