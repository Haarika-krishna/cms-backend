// utils/emailservice.js
const nodemailer = require('nodemailer');

const createTransporter = () => {
  if (process.env.NODE_ENV === 'production' && process.env.SENDGRID_API_KEY) {
    // SendGrid via SMTP
    return nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 587,
      secure: false,
      auth: {
        user: 'apikey',
        pass: process.env.SENDGRID_API_KEY
      }
    });
  }

  // Development/test - use Gmail or ethereal
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD
    }
  });
};

const transporter = createTransporter();

const sendVerificationEmail = async ({ email, name, verificationToken }) => {
  const verificationUrl = `${process.env.BASE_URL}/api/customer/verify-email?token=${verificationToken}`;

  const mailOptions = {
    from: `"Your App Name" <${process.env.EMAIL_FROM}>`,
    to: email,
    subject: 'Verify Your Email Address',
    html: `<p>Hello ${name},</p>
           <p>Please verify your email by clicking the link below:</p>
           <a href="${verificationUrl}">Verify Email</a>
           <p>This link expires in 24 hours.</p>`,
    text: `Hello ${name},\nPlease verify your email:\n${verificationUrl}\n`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
    return true;
  } catch (err) {
    console.error('Error sending verification email:', err && (err.response?.body || err.message || err));
    throw err;
  }
};

module.exports = { sendVerificationEmail };