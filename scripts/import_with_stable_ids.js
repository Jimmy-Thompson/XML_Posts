import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

// Generate stable ID from job URL
function generateStableId(jobUrl) {
  if (!jobUrl) {
    throw new Error('Job URL is required for stable ID generation');
  }
  const hash = crypto.createHash('md5').update(jobUrl).digest('hex');
  // Use first 10 characters for readability
  return hash.substring(0, 10);
}

// Validate job has minimum required fields
function isValidJob(job) {
  return (
    job.job_url &&
    job.title &&
    job.company &&
    job.city &&
    job.state
  );
}

// Import jobs with stable IDs
function importJobsWithStableIds(jsonFilePath, dbPath) {
  console.log('Starting import with stable hash-based IDs...\n');
  
  // Read JSON file
  console.log(`Reading: ${jsonFilePath}`);
  const jsonData = JSON.parse(fs.readFileSync(jsonFilePath, 'utf8'));
  console.log(`✓ Loaded ${jsonData.length} jobs\n`);
  
  // Create new database
  if (fs.existsSync(dbPath)) {
    fs.unlinkSync(dbPath);
    console.log('✓ Removed old database\n');
  }
  
  const db = new Database(dbPath);
  
  // Create jobs table
  console.log('Creating jobs table...');
  db.exec(`
    CREATE TABLE jobs (
      id TEXT PRIMARY KEY,
      job_url TEXT NOT NULL,
      title TEXT NOT NULL,
      company TEXT NOT NULL,
      city TEXT NOT NULL,
      state TEXT NOT NULL,
      address TEXT,
      description TEXT,
      general_requirements TEXT,
      pay TEXT,
      benefits TEXT,
      vehicle_requirements TEXT,
      insurance_requirement TEXT,
      certifications_required TEXT,
      schedule_details TEXT,
      source_company TEXT,
      scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX idx_jobs_city_state ON jobs(city, state);
    CREATE INDEX idx_jobs_company ON jobs(company);
    CREATE INDEX idx_jobs_source ON jobs(source_company);
  `);
  console.log('✓ Table created\n');
  
  // Prepare insert statement
  const insert = db.prepare(`
    INSERT INTO jobs (
      id, job_url, title, company, city, state, address, description,
      general_requirements, pay, benefits, vehicle_requirements,
      insurance_requirement, certifications_required, schedule_details,
      source_company, scraped_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  // Import jobs with stable IDs using transaction
  console.log('Importing jobs...');
  let imported = 0;
  let duplicates = 0;
  let skipped = 0;
  const idMap = new Map();
  
  // Wrap in transaction for performance
  const insertMany = db.transaction((jobs) => {
    for (const job of jobs) {
      // Skip invalid jobs (missing required fields)
      if (!isValidJob(job)) {
        skipped++;
        continue;
      }
      
      const stableId = generateStableId(job.job_url);
      
      // Track duplicates (same URL = same ID)
      if (idMap.has(stableId)) {
        duplicates++;
        continue;
      }
      idMap.set(stableId, job.job_url);
      
      try {
        insert.run(
          stableId,
          job.job_url,
          job.title,
          job.company,
          job.city,
          job.state,
          job.address || null,
          job.description || null,
          job.general_requirements || null,
          job.pay || null,
          job.benefits || null,
          job.vehicle_requirements || null,
          job.insurance_requirement || null,
          job.certifications_required || null,
          job.schedule_details || null,
          job.source_company || null,
          job.scraped_at || new Date().toISOString()
        );
        imported++;
        
        if (imported % 1000 === 0) {
          console.log(`  Imported ${imported} jobs...`);
        }
      } catch (err) {
        console.error(`Error importing job: ${job.title}`, err.message);
      }
    }
  });
  
  insertMany(jsonData);
  
  console.log(`\n✓ Imported ${imported} jobs`);
  if (duplicates > 0) {
    console.log(`  Skipped ${duplicates} duplicates (same URL)`);
  }
  if (skipped > 0) {
    console.log(`  Skipped ${skipped} invalid jobs (missing required fields)`);
  }
  
  // Show sample of stable IDs
  console.log('\n📋 Sample of stable IDs generated:');
  const samples = db.prepare('SELECT id, title, job_url FROM jobs LIMIT 5').all();
  samples.forEach(job => {
    console.log(`  ${job.id} → ${job.title}`);
    console.log(`    ${job.job_url.substring(0, 60)}...`);
  });
  
  // Test ID stability
  console.log('\n🔬 Testing ID stability...');
  const testJob = samples[0];
  const regeneratedId = generateStableId(testJob.job_url);
  if (regeneratedId === testJob.id) {
    console.log('  ✅ ID regeneration is stable!');
    console.log(`  Same URL always produces: ${regeneratedId}`);
  } else {
    console.log('  ❌ WARNING: ID regeneration failed!');
  }
  
  db.close();
  console.log('\n✅ Import complete!\n');
  
  return {
    imported,
    duplicates,
    skipped,
    totalUnique: idMap.size
  };
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const jsonPath = process.argv[2] || 'attached_assets/master_jobs_all_1762897931599.json';
  const dbPath = process.argv[3] || 'outputs/master_database/master_jobs_test.db';
  
  try {
    const stats = importJobsWithStableIds(jsonPath, dbPath);
    console.log('📊 Final Stats:');
    console.log(`  Total jobs imported: ${stats.imported}`);
    console.log(`  Unique job URLs: ${stats.totalUnique}`);
    console.log(`  Duplicates skipped: ${stats.duplicates}`);
    console.log(`  Invalid jobs skipped: ${stats.skipped}`);
    process.exit(0);
  } catch (err) {
    console.error('❌ Import failed:', err);
    process.exit(1);
  }
}

export { importJobsWithStableIds, generateStableId };
