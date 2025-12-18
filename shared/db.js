import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const MASTER_DB_PATH = path.join(__dirname, '..', 'outputs', 'master_database', 'master_jobs.db');
const USER_DB_PATH = path.join(__dirname, '..', 'outputs', 'user_jobs.db');

let masterDbInstance = null;
let userDbInstance = null;

export function getDb() {
  if (!masterDbInstance) {
    masterDbInstance = new Database(MASTER_DB_PATH);
  }
  return masterDbInstance;
}

export function getUserDb() {
  if (!userDbInstance) {
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
