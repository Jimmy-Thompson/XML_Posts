import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const OUTPUTS_DIR = path.join(__dirname, '..', 'outputs');
const MASTER_DB_DIR = path.join(OUTPUTS_DIR, 'master_database');
const MASTER_DB_PATH = path.join(MASTER_DB_DIR, 'master_jobs.db');
const USER_DB_PATH = path.join(OUTPUTS_DIR, 'user_jobs.db');

function ensureDirectories() {
  if (!fs.existsSync(OUTPUTS_DIR)) {
    fs.mkdirSync(OUTPUTS_DIR, { recursive: true });
    console.log('[db] Created outputs directory');
  }
  if (!fs.existsSync(MASTER_DB_DIR)) {
    fs.mkdirSync(MASTER_DB_DIR, { recursive: true });
    console.log('[db] Created master_database directory');
  }
}

let masterDbInstance = null;
let userDbInstance = null;

export function getDb() {
  if (!masterDbInstance) {
    ensureDirectories();
    masterDbInstance = new Database(MASTER_DB_PATH);
  }
  return masterDbInstance;
}

export function getUserDb() {
  if (!userDbInstance) {
    ensureDirectories();
    userDbInstance = new Database(USER_DB_PATH);
  }
  return userDbInstance;
}

export function closeDb() {
  if (masterDbInstance) {
    masterDbInstance.close();
    masterDbInstance = null;
  }
  if (userDbInstance) {
    userDbInstance.close();
    userDbInstance = null;
  }
}
