// middlewares/auth.js
const jwt = require('jsonwebtoken');
const Customer = require('../models/Customer');

exports.protect = async (req, res, next) => {
  try {
    let token;

    // 1) Authorization header (Bearer ...)
    if (req.headers.authorization && req.headers.authorization.split(' ')[0].toLowerCase() === 'bearer') {
      token = req.headers.authorization.split(' ')[1];
    }

    // 2) Cookie (if you use cookie auth) - optional
    if (!token && req.cookies && req.cookies.token) {
      token = req.cookies.token;
    }

    if (!token) {
      return res.status(401).json({ status: 'fail', message: 'You are not logged in.' });
    }

    if (!process.env.JWT_SECRET) {
      console.warn('JWT_SECRET not set - protect will still try to verify with fallback secret');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');

    const currentCustomer = await Customer.findById(decoded.id).select('+password');
    if (!currentCustomer) {
      return res.status(401).json({ status: 'fail', message: 'User no longer exists.' });
    }

    // Check if user changed password after token was issued
    if (currentCustomer.changedPasswordAfter && currentCustomer.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({ status: 'fail', message: 'User recently changed password. Please log in again.' });
    }

    // attach safe user object (without password)
    req.customer = {
      id: currentCustomer._id,
      name: currentCustomer.name,
      email: currentCustomer.email
    };
    next();
  } catch (err) {
    console.error('Authentication error:', err);
    let message = 'Invalid token. Please log in again.';
    if (err.name === 'TokenExpiredError') message = 'Your token has expired. Please log in again.';

    res.status(401).json({ status: 'fail', message });
  }
};