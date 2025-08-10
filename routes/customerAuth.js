// routes/customerAuth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const Customer = require('../models/customer');
const { sendVerificationEmail } = require('../utils/emailService');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

/**
 * Helper: create JWT
 */
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

/**
 * POST /api/customer/signup
 */
router.post(
  '/signup',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Provide a valid email'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ status: 'fail', errors: errors.array() });

      const { name, email, password } = req.body;
      const cleanedEmail = email.trim().toLowerCase();

      const existing = await Customer.findOne({ email: cleanedEmail });
      if (existing) return res.status(409).json({ status: 'fail', message: 'Email already exists' });

      // Create customer - model pre-save will hash password (and skip if already hashed)
      const customer = new Customer({
        name: name.trim(),
        email: cleanedEmail,
        password: password
      });

      await customer.save();

      // Optionally generate verification token & send email (commented out if not used)
      // const verificationToken = crypto.randomBytes(32).toString('hex');
      // customer.verificationToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
      // customer.verificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000;
      // await customer.save();
      // await sendVerificationEmail({ email: customer.email, name: customer.name, verificationToken });

      const token = signToken({ id: customer._id });

      res.status(201).json({
        success: true,
        message: 'Registration successful',
        token,
        user: { id: customer._id, name: customer.name, email: customer.email }
      });
    } catch (err) {
      console.error('Signup error:', err && err.stack ? err.stack : err);
      if (err.code === 11000) return res.status(409).json({ success: false, message: 'Email already exists' });
      next(err);
    }
  }
);

/**
 * POST /api/customer/signin
 */
router.post(
  '/signin',
  [
    body('email').isEmail().withMessage('Provide a valid email'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });

      let { email, password } = req.body;
      email = email.trim().toLowerCase();
      password = typeof password === 'string' ? password.trim() : password;

      console.log(`[AUTH] Signin attempt for ${email} (ip=${req.ip})`);

      // explicitly select password (schema uses select:false)
      const user = await Customer.findOne({ email }).select('+password +passwordChangedAt +active');
      if (!user) {
        console.log('[AUTH] User not found');
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
      }

      // If user is inactive
      if (user.active === false) {
        return res.status(403).json({ success: false, message: 'Account is deactivated' });
      }

      // Debug prints (safe truncated)
      console.log('[AUTH] Stored hash prefix:', user.password ? user.password.substring(0, 15) + '...' : '(no-hash)');

      // Compare passwords
      const isMatch = await user.comparePassword(password);
      console.log('[AUTH] bcrypt compare result:', isMatch);

      if (!isMatch) {
        // also try trimmed (front-end sometimes sends trailing spaces)
        const trimmedMatch = await user.comparePassword(password.trim());
        console.log('[AUTH] trimmed compare result:', trimmedMatch);

        return res.status(401).json({
          success: false,
          message: 'Invalid credentials',
          debug: {
            inputLength: password ? password.length : 0,
            trimmedDifferent: password !== (password || '').trim()
          }
        });
      }

      // Check password changed after token (just demonstration)
      // if (user.changedPasswordAfter(decoded.iat)) { ... }

      const token = signToken({ id: user._id });

      // Make sure we don't return password
      const safeUser = {
        id: user._id,
        name: user.name,
        email: user.email
      };

      res.json({ success: true, token, user: safeUser });
    } catch (err) {
      console.error('Signin error:', err && err.stack ? err.stack : err);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);

/**
 * POST /api/customer/force-reset
 * Body: { email, newPassword } - immediate reset (admin/dev)
 */
router.post('/force-reset', async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) return res.status(400).json({ success: false, message: 'email and newPassword required' });

  const cleaned = email.trim().toLowerCase();
  const user = await Customer.findOne({ email: cleaned }).select('+password');
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });

  user.password = newPassword; // pre-save will hash
  await user.save();

  res.json({ success: true, message: 'Password reset successful' });
});

/**
 * POST /api/customer/verify-password   (debug helper)
 * Body: { email, password }
 */
router.post('/verify-password', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const user = await Customer.findOne({ email: email.trim().toLowerCase() }).select('+password');
  if (!user) return res.status(404).json({ error: 'User not found' });

  console.log('====== PASSWORD VERIFICATION ======');
  console.log('Input password:', `"${password}"`, 'Length:', password.length);
  console.log('Stored hash:', user.password);

  const isMatch = await user.comparePassword(password);
  console.log('Bcrypt compare result:', isMatch);

  // Also show whether newly hashing the raw input equals stored (it shouldn't)
  const testHash = await bcrypt.hash(password, 12);
  console.log('New hash of input:', testHash);
  console.log('New hash matches stored:', testHash === user.password);

  res.json({
    inputPassword: password,
    storedHash: user.password,
    isMatch,
    testHash,
    hashMatches: testHash === user.password
  });
});

/**
 * Development helper: migrate plaintext passwords to bcrypt hashed form.
 * Only allowed in development.
 */
router.post('/migrate-passwords', async (req, res) => {
  if (process.env.NODE_ENV !== 'development') return res.status(403).json({ success: false, message: 'Forbidden' });

  try {
    const users = await Customer.find({}).select('+password');
    let migrated = 0;
    for (const u of users) {
      if (!u.password || typeof u.password !== 'string') continue;
      if (u.password.startsWith('$2')) {
        console.log(`Already hashed: ${u.email}`);
        continue;
      }
      // set plaintext into field and save (pre-save will hash)
      const original = u.password;
      u.password = original;
      await u.save();
      migrated++;
      console.log(`Migrated ${u.email}`);
    }
    res.json({ success: true, migrated, total: users.length });
  } catch (err) {
    console.error('Migration error:', err);
    res.status(500).json({ success: false, message: 'Migration failed' });
  }
});

module.exports = router;