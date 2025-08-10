// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();

// Basic middlewares
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS - read allowed origin from env (fallback to localhost:3000)
const FRONTEND = process.env.BASE_URL || 'http://localhost:3000';
app.use(cors({
  origin: (origin, cb) => {
    // allow requests with no origin (like mobile apps, curl, postman)
    if (!origin) return cb(null, true);
    if (origin === FRONTEND) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Log incoming requests (simple)
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
  next();
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Mount customer auth routes
app.use('/api/customer', require('./routes/customerAuth'));

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// 404
app.use((req, res) => {
  res.status(404).json({ status: 'fail', message: 'Not Found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('GLOBAL ERROR:', err && err.stack ? err.stack : err);
  res.status(err.status || 500).json({
    status: 'error',
    message: err.message || 'Internal Server Error'
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});