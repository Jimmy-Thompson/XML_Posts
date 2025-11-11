import Database from 'better-sqlite3';
import { generateStableId } from './import_with_stable_ids.js';

console.log('🔬 Testing ID Stability Across Imports\n');

const db = new Database('outputs/master_database/master_jobs_test.db');

// Get 10 random jobs
const jobs = db.prepare('SELECT id, job_url, title FROM jobs ORDER BY RANDOM() LIMIT 10').all();

console.log('Testing 10 random jobs...\n');

let allStable = true;

jobs.forEach((job, idx) => {
  const regeneratedId = generateStableId(job.job_url);
  const matches = regeneratedId === job.id;
  
  console.log(`${idx + 1}. ${job.title}`);
  console.log(`   Database ID: ${job.id}`);
  console.log(`   Regenerated: ${regeneratedId}`);
  console.log(`   Status: ${matches ? '✅ STABLE' : '❌ MISMATCH'}\n`);
  
  if (!matches) allStable = false;
});

db.close();

if (allStable) {
  console.log('🎉 All IDs are stable! Analytics will persist across imports.\n');
} else {
  console.log('⚠️  Warning: Some IDs are not stable!\n');
  process.exit(1);
}
