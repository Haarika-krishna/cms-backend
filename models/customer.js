// models/customer.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const CustomerSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [8, 'Password must be at least 8 characters'],
    select: false
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  verificationTokenExpires: Date,
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false
  }
}, { timestamps: true });

// Index for faster lookups
CustomerSchema.index({ email: 1 });

/**
 * Pre-save: hash password only if modified and only if it doesn't already look like a bcrypt hash.
 * This avoids double-hashing if other code accidentally hashes before saving.
 */
CustomerSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  // If the password already looks like a bcrypt hash, skip hashing
  if (typeof this.password === 'string' && this.password.startsWith('$2')) {
    return next();
  }

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    // set passwordChangedAt slightly in the past to avoid token timing issues
    this.passwordChangedAt = Date.now() - 1000;
    next();
  } catch (err) {
    next(err);
  }
});

/**
 * Instance method: compare a plain text password to the stored hash.
 * Use customer.comparePassword(password) from route code.
 */
CustomerSchema.methods.comparePassword = async function(candidatePassword) {
  if (!candidatePassword) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

/**
 * Check if the user changed password after JWT issuance.
 */
CustomerSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

/**
 * Create password reset token (raw token returned; hashed stored)
 */
CustomerSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

/**
 * Hide sensitive fields when sending to clients
 */
CustomerSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.password;
  delete obj.__v;
  return obj;
};

module.exports = mongoose.model('Customer', CustomerSchema);