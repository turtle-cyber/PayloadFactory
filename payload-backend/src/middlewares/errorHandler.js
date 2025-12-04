import { HTTP_STATUS } from "../config/constants.js";
import { logger } from "../utils/logger.js";

/**
 * Global error handler middleware
 * Catches all errors and sends a formatted response
 */
export const errorHandler = (err, req, res, next) => {
  // Log the error
  logger.error("Error occurred", {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });

  // Default error status and message
  const statusCode =
    err.statusCode || err.status || HTTP_STATUS.INTERNAL_SERVER_ERROR;
  const message = err.message || "Internal server error";

  // Send error response
  res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === "development" && {
      stack: err.stack,
      error: err,
    }),
  });
};

/**
 * 404 Not Found handler
 * Catches all undefined routes
 */
export const notFoundHandler = (req, res, next) => {
  const error = new Error(`Route not found - ${req.originalUrl}`);
  error.statusCode = HTTP_STATUS.NOT_FOUND;
  next(error);
};
