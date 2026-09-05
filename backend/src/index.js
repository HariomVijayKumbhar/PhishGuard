import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import scanRouter from './routes/scan.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:5173';

// Basic middleware
app.use(cors({
  origin: ALLOWED_ORIGIN === '*' ? '*' : ALLOWED_ORIGIN.split(',').map(o => o.trim()),
  credentials: true
}));
app.use(express.json({ limit: '5mb' }));

// API Routes
app.use('/api', scanRouter);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Root ping
app.get('/', (req, res) => {
  res.status(200).json({
    service: 'PhishGuard API',
    status: 'online',
    version: '1.0.0'
  });
});

// Centralized error handling middleware (Guarantees strict JSON, no HTML/stack traces)
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large' || err.status === 413 || err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      error: 'Request payload exceeds maximum allowed limit (5MB)',
      code: 'PAYLOAD_TOO_LARGE',
      requestId: `req_${Date.now().toString(36)}`
    });
  }

  console.error('[Internal Error]', err.message);
  res.status(err.status || 500).json({
    error: 'Internal server error processing request',
    code: err.code || 'INTERNAL_ERROR',
    requestId: `req_${Date.now().toString(36)}`
  });
});

import { fileURLToPath } from 'url';

// Start server only when invoked directly (not when imported in tests)
const isDirectRun = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];

if (isDirectRun && process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`[PhishGuard Backend] Running on http://localhost:${PORT}`);
  });
}

export default app;
