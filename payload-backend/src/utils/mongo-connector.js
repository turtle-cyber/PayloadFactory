// Mongo singleton with logger + envs
import { MongoClient } from "mongodb";
import { logger } from "./logger.js";

let client = null;
let db = null;
let status = "init"; // init | ok | error

async function initMongo() {
  if (db) return db; // already initialized

  const uri = process.env.MONGO_URI;
  const dbName = process.env.MONGO_DB;
  const username = process.env.MONGO_USERNAME;
  const password = process.env.MONGO_PASSWORD;

  if (!uri || !dbName) {
    const missing = ["MONGO_URI", "MONGO_DB"].filter((k) => !process.env[k]);
    const err = new Error(`Missing required env vars: ${missing.join(", ")}`);
    err.code = "ENV_MISSING";
    status = "error";
    logger.error(
      `MongoDB initialization failed: Missing required env vars: ${missing.join(
        ", "
      )}`
    );
    throw err;
  }

  logger.info(`Attempting to connect to MongoDB...`);

  const maxPoolSize = Number(process.env.MONGO_MAX_POOL || 50);

  // Build connection options
  const options = {
    maxPoolSize,
  };

  // Add authentication if credentials are provided
  if (username && password) {
    options.auth = {
      username,
      password,
    };
    // Try admin database for authentication first (most common)
    options.authSource = process.env.MONGO_AUTH_SOURCE || "admin";
    logger.info(`Connecting with authentication enabled (authSource: ${options.authSource})`);
  } else {
    logger.info("Connecting without authentication");
  }

  client = new MongoClient(uri, options);

  try {
    await client.connect();
    logger.info("MongoDB client connected successfully");

    db = client.db(dbName);
    await db.command({ ping: 1 });

    status = "ok";
    logger.info(
      `MongoDB connection established successfully (db=${dbName}, pool=${maxPoolSize})`
    );
    return db;
  } catch (e) {
    status = "error";
    logger.error(`MongoDB connection failed: ${e.message}`, {
      error: e.message,
      code: e.code,
      stack: e.stack,
    });
    throw e;
  }
}

function getDb() {
  if (!db) throw new Error("Mongo not initialized. Call initMongo() first.");
  return db;
}

/**
 * Helper to run any DB operation with the already-initialized db.
 * Usage:
 *   const users = await runOnDb(db => db.collection('users').find().toArray());
 */
async function runOnDb(fn) {
  const database = getDb();
  return fn(database);
}

async function closeMongo() {
  try {
    if (client) {
      logger.info("Closing MongoDB connection...");
      await client.close();
      logger.info("MongoDB connection closed gracefully");
    }
  } catch (e) {
    logger.error(`Error closing MongoDB connection: ${e.message}`);
  } finally {
    client = null;
    db = null;
    status = "init";
  }
}

function mongoStatus() {
  return status;
}

export { initMongo, getDb, runOnDb, closeMongo, mongoStatus };
