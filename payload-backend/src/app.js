import express from "express";
import cors from "cors";
import "dotenv/config";
import { httpLogger, logger } from "./utils/logger.js";
import { initMongo, mongoStatus, closeMongo } from "./utils/mongo-connector.js";
import cookieParser from "cookie-parser";
import apiRoutes from "./routes/index.js";
import {
  errorHandler,
  notFoundHandler,
} from "./middlewares/errorHandler.js";

const app = express();

const PORT = Number(process.env.PORT) || 5000;
const HOST = process.env.HOST || "0.0.0.0";

app.set("etag", false);
app.set("trust proxy", true);
app.use(cors({}));

// NEW: request logging
app.use(httpLogger);

app.get("/health", (_, res) =>
  res.json({
    ok: mongoStatus() === "ok",
    mongodb: mongoStatus(),
  })
);

app.use("/api", (req, res, next) => {
  res.set(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, proxy-revalidate"
  );
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.set("Surrogate-Control", "no-store");
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Root endpoint
app.get("/", (req, res) => {
  res.send("Payload Factory API is running ✅");
});

// Mount API routes
app.use("/api", apiRoutes);

// 404 handler for undefined routes
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(errorHandler);
(async () => {
  try {
    // Initialize MongoDB
    await initMongo(); // reads MONGO_URI + MONGO_DB from env

    const server = app.listen(PORT, HOST, () => {
      logger.info(
        `Payload Factory Backend listening on http://${HOST}:${PORT}`
      );
    });

    // Graceful shutdown
    const shutdown = async (sig) => {
      logger.warn(`${sig} signal received, initiating graceful shutdown...`);

      try {
        await closeMongo();
      } catch (e) {
        logger.error("Mongo close error", { message: e.message });
      }

      server.close(async () => {
        logger.info("HTTP server closed");

        // Give logger time to flush before exiting
        // Using setTimeout instead of Promise to ensure it runs synchronously
        setTimeout(() => {
          process.exit(0);
        }, 150);
      });

      // Force exit after 8 seconds if graceful shutdown fails
      setTimeout(() => {
        logger.error("Graceful shutdown timed out, forcing exit");
        process.exit(1);
      }, 8000).unref();
    };
    process.on("SIGINT", () => shutdown("SIGINT"));
    process.on("SIGTERM", () => shutdown("SIGTERM"));
  } catch (err) {
    logger.error("Failed to start server", { message: err.message });
    process.exit(1);
  }
})();
