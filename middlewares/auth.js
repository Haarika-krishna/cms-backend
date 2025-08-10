const jwt = require('jsonwebtoken');
const Customer = require('../models/customer');

// Protect routes - customer must be authenticated
exports.protect = async (req, res, next) => {
  try {
    // 1. Get token from header
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith('Bearer')
    ) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in. Please log in to get access.'
      });
    }

    // 2. Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 3. Check if customer still exists
    const currentCustomer = await Customer.findById(decoded.id);
    if (!currentCustomer) {
      return res.status(401).json({
        status: 'fail',
        message: 'The customer belonging to this token no longer exists.'
      });
    }

    // 4. Check if customer changed password after token was issued
    if (currentCustomer.changedPasswordAfter(decoded.iat)) {
      return res.status(401).json({
        status: 'fail',
        message: 'Customer recently changed password. Please log in again.'
      });
    }

    // Grant access to protected route
    req.customer = currentCustomer;
    next();
  } catch (err) {
    console.error('Authentication error:', err);
    
    let message = 'Invalid token. Please log in again.';
    if (err.name === 'TokenExpiredError') {
      message = 'Your token has expired. Please log in again.';
    } else if (err.name === 'JsonWebTokenError') {
      message = 'Invalid token. Please log in again.';
    }

    res.status(401).json({
      status: 'fail',
      message
    });
  }
};