import dotenv from 'dotenv';

// Set the NODE_ENV to 'development' by default
process.env.NODE_ENV = process.env.NODE_ENV || 'development';

const envFound = dotenv.config();
if (envFound.error) {
  // This error should crash whole process

  throw new Error("⚠️  Couldn't find .env file  ⚠️");
}

export default {
  /**
   * port
   */
  port: process.env.PORT,

  /**
   * mongoose information
   */
  mongoUsername: process.env.MONGO_USERNAME,
  mongoPassword: process.env.MONGO_PASSWORD,
  mongoHostname: process.env.MONGO_HOSTNAME,
  mongoPort: process.env.MONGO_PORT,
  mongoDatabase: process.env.MONGO_DB,

  /**
   * used by winston logger
   */
  logs: {
    level: process.env.LOG_LEVEL || 'silly',
  }
}