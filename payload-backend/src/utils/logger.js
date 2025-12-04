import log4js from "log4js";

// Configure log4js with colored console output
log4js.configure({
  appenders: {
    console: {
      type: "console",
      layout: {
        type: "pattern",
        pattern: "%[[%d{dd-MM-yyyy hh:mm:ss}] [%p]%] %m",
      },
    },
  },
  categories: {
    default: {
      appenders: ["console"],
      level: process.env.LOG_LEVEL || "info",
    },
  },
});

// Create the main logger
export const logger = log4js.getLogger();

// HTTP logger middleware for Express
export const httpLogger = (req, res, next) => {
  const start = Date.now();

  // Log after response is sent
  res.on("finish", () => {
    const duration = Date.now() - start;
    const logLevel =
      res.statusCode >= 500
        ? "error"
        : res.statusCode >= 400
        ? "warn"
        : "info";

    logger[logLevel](
      `Method: ${req.method} | Route: ${req.url} | Code: ${res.statusCode} | Response-Time: ${duration} ms`
    );
  });

  next();
};
