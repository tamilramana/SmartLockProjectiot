const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const DATA_FILE = path.join(__dirname, 'data.json');

// Memory cache to avoid constant disk reads if we want, but reading is fine if we lock writes
let writeLock = false;
let writeQueue = [];

// A simple queue to ensure writes are atomic and don't overlap
async function executeWithLock(task) {
  return new Promise((resolve, reject) => {
    writeQueue.push({ task, resolve, reject });
    processQueue();
  });
}

async function processQueue() {
  if (writeLock || writeQueue.length === 0) return;
  writeLock = true;
  
  const { task, resolve, reject } = writeQueue.shift();
  try {
    const result = await task();
    resolve(result);
  } catch (err) {
    reject(err);
  } finally {
    writeLock = false;
    processQueue(); // process next
  }
}

async function loadData() {
  try {
    const content = await fs.readFile(DATA_FILE, 'utf8');
    return JSON.parse(content);
  } catch (err) {
    if (err.code === 'ENOENT') {
      const initial = { users: [], devices: [], logs: [], notifications: [], schedules: [] };
      await saveData(initial);
      return initial;
    }
    throw err;
  }
}

// Low level save
async function saveData(data) {
  return executeWithLock(async () => {
    const tempFile = `${DATA_FILE}.tmp`;
    await fs.writeFile(tempFile, JSON.stringify(data, null, 2), 'utf8');
    await fs.rename(tempFile, DATA_FILE); // Atomic replace
  });
}

// Wrapper to modify data
async function modifyData(modifierFn) {
  return executeWithLock(async () => {
    let data;
    try {
      const content = await fs.readFile(DATA_FILE, 'utf8');
      data = JSON.parse(content);
    } catch (e) {
      if (e.code === 'ENOENT') {
        data = { users: [], devices: [], logs: [], notifications: [], schedules: [] };
      } else {
        throw e;
      }
    }
    
    await modifierFn(data);
    
    const tempFile = `${DATA_FILE}.tmp`;
    await fs.writeFile(tempFile, JSON.stringify(data, null, 2), 'utf8');
    await fs.rename(tempFile, DATA_FILE);
    return data;
  });
}

module.exports = {
  loadData,
  saveData,
  modifyData
};
