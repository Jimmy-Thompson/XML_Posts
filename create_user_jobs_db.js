import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const MASTER_DB_PATH = path.join(__dirname, 'outputs', 'master_database', 'master_jobs.db');
const USER_DB_PATH = path.join(__dirname, 'outputs', 'master_database', 'user_jobs.db');

console.log('Creating user_jobs.db database...');

// Open master DB to get schema
const masterDb = new Database(MASTER_DB_PATH, { readonly: true });
console.log('Opened master database');

// Get the jobs table schema
const schema = masterDb.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='jobs'").get();
console.log('Jobs table schema:', schema);

// Get indexes
const indexes = masterDb.prepare("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='jobs'").all();
console.log('Indexes:', indexes);

masterDb.close();

// Create new user jobs database
const userDb = new Database(USER_DB_PATH);
console.log('Created user_jobs.db');

// Create jobs table with same schema
if (schema && schema.sql) {
  userDb.exec(schema.sql);
  console.log('Created jobs table');
}

// Create indexes
indexes.forEach(index => {
  if (index.sql) {
    userDb.exec(index.sql);
    console.log('Created index:', index.sql.substring(0, 50));
  }
});

// Verify table was created
const tableInfo = userDb.prepare("PRAGMA table_info(jobs)").all();
console.log('\nUser jobs table columns:');
tableInfo.forEach(col => {
  console.log(`  ${col.name}: ${col.type}`);
});

userDb.close();
console.log('\nuser_jobs.db created successfully!');
