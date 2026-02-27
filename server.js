require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── SECURITY MIDDLEWARE ──────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // We serve our own HTML
}));

// CORS - Only allow your own domain
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000'];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (same-origin, Postman for testing)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS policy: origin not allowed'), false);
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Serve static HTML file
app.use(express.static(path.join(__dirname, 'public')));

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // max 5 submissions per IP per 15 minutes
  message: { success: false, message: 'Too many requests. Please wait 15 minutes and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60, // max 60 requests per minute per IP (for page loads etc.)
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(globalLimiter);

// ─── NODEMAILER TRANSPORTER ───────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,       // e.g. mail.yourdomain.com
  port: parseInt(process.env.SMTP_PORT) || 465,
  secure: process.env.SMTP_PORT === '465', // true for 465, false for 587
  auth: {
    user: process.env.SMTP_USER,     // your cPanel email e.g. info@yourdomain.com
    pass: process.env.SMTP_PASS,     // cPanel email password
  },
  tls: {
    rejectUnauthorized: true,
  },
});

// Verify transporter on startup
transporter.verify(function (error) {
  if (error) {
    console.error('❌ SMTP Connection Error:', error.message);
  } else {
    console.log('✅ SMTP Server is ready to send emails');
  }
});

// ─── HELPER: Sanitize string ──────────────────────────────────────────────────
function sanitize(str) {
  if (!str) return '';
  return String(str)
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .trim()
    .substring(0, 500); // hard cap at 500 chars
}

// ─── ROUTE: Health Check ─────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── ROUTE: Booking Form ─────────────────────────────────────────────────────
app.post('/api/booking',
  formLimiter,
  [
    body('firstName').trim().notEmpty().isLength({ max: 50 }).escape(),
    body('lastName').trim().notEmpty().isLength({ max: 50 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('date').notEmpty().isISO8601().toDate(),
    body('time').notEmpty().trim().isLength({ max: 20 }).escape(),
  ],
  async (req, res) => {
    // Validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: 'Invalid form data. Please check all fields.' });
    }

    const { firstName, lastName, email, date, time } = req.body;
    const safeFirst = sanitize(firstName);
    const safeLast = sanitize(lastName);
    const safeEmail = sanitize(email);
    const safeDate = new Date(date).toLocaleDateString('en-US', { weekday:'long', year:'numeric', month:'long', day:'numeric' });
    const safeTime = sanitize(time);

    const mailOptions = {
      from: `"LWA Website" <${process.env.SMTP_USER}>`,
      to: process.env.BUSINESS_EMAIL,
      replyTo: safeEmail,
      subject: `📅 New Booking Request — ${safeFirst} ${safeLast}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;background:#f9f9f9;padding:30px;border-radius:8px;">
          <div style="background:#080c0a;padding:20px;border-radius:6px 6px 0 0;text-align:center;">
            <h2 style="color:#00e87a;margin:0;font-size:22px;">LWA Leads Group</h2>
            <p style="color:#7a9484;margin:6px 0 0;font-size:13px;">New Booking Request</p>
          </div>
          <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;border-top:none;">
            <table style="width:100%;border-collapse:collapse;">
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666;width:35%;font-size:14px;"><strong>Full Name</strong></td>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#222;font-size:14px;">${safeFirst} ${safeLast}</td>
              </tr>
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666;font-size:14px;"><strong>Email</strong></td>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#222;font-size:14px;">${safeEmail}</td>
              </tr>
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666;font-size:14px;"><strong>Preferred Date</strong></td>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#222;font-size:14px;">${safeDate}</td>
              </tr>
              <tr>
                <td style="padding:10px 0;color:#666;font-size:14px;"><strong>Preferred Time</strong></td>
                <td style="padding:10px 0;color:#222;font-size:14px;">${safeTime}</td>
              </tr>
            </table>
            <div style="margin-top:20px;padding:12px;background:#f0fdf4;border-left:3px solid #00e87a;border-radius:4px;">
              <p style="margin:0;font-size:13px;color:#444;">💡 Hit <strong>Reply</strong> to respond directly to ${safeFirst}.</p>
            </div>
          </div>
          <p style="text-align:center;color:#aaa;font-size:11px;margin-top:16px;">Sent from LWA Leads Group website</p>
        </div>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log(`✅ Booking email sent for ${safeEmail} at ${new Date().toISOString()}`);
      res.json({ success: true, message: 'Booking confirmed! We will be in touch shortly.' });
    } catch (err) {
      console.error('❌ Booking email failed:', err.message);
      res.status(500).json({ success: false, message: 'Failed to send. Please try again or contact us directly.' });
    }
  }
);

// ─── ROUTE: Contact Form ─────────────────────────────────────────────────────
app.post('/api/contact',
  formLimiter,
  [
    body('name').trim().notEmpty().isLength({ max: 100 }).escape(),
    body('email').isEmail().normalizeEmail(),
    body('message').trim().notEmpty().isLength({ min: 10, max: 2000 }).escape(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, message: 'Invalid form data. Please check all fields.' });
    }

    const { name, email, message } = req.body;
    const safeName = sanitize(name);
    const safeEmail = sanitize(email);
    const safeMessage = sanitize(message);

    const mailOptions = {
      from: `"LWA Website" <${process.env.SMTP_USER}>`,
      to: process.env.BUSINESS_EMAIL,
      replyTo: safeEmail,
      subject: `✉️ New Message from ${safeName}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;background:#f9f9f9;padding:30px;border-radius:8px;">
          <div style="background:#080c0a;padding:20px;border-radius:6px 6px 0 0;text-align:center;">
            <h2 style="color:#00e87a;margin:0;font-size:22px;">LWA Leads Group</h2>
            <p style="color:#7a9484;margin:6px 0 0;font-size:13px;">New Contact Message</p>
          </div>
          <div style="background:#fff;padding:24px;border-radius:0 0 6px 6px;border:1px solid #e0e0e0;border-top:none;">
            <table style="width:100%;border-collapse:collapse;">
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666;width:25%;font-size:14px;"><strong>Name</strong></td>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#222;font-size:14px;">${safeName}</td>
              </tr>
              <tr>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666;font-size:14px;"><strong>Email</strong></td>
                <td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#222;font-size:14px;">${safeEmail}</td>
              </tr>
            </table>
            <div style="margin-top:20px;">
              <p style="color:#666;font-size:14px;margin-bottom:8px;"><strong>Message:</strong></p>
              <div style="background:#f8f8f8;padding:16px;border-radius:4px;border:1px solid #eee;color:#333;font-size:14px;line-height:1.7;white-space:pre-wrap;">${safeMessage}</div>
            </div>
            <div style="margin-top:20px;padding:12px;background:#f0fdf4;border-left:3px solid #00e87a;border-radius:4px;">
              <p style="margin:0;font-size:13px;color:#444;">💡 Hit <strong>Reply</strong> to respond directly to ${safeName}.</p>
            </div>
          </div>
          <p style="text-align:center;color:#aaa;font-size:11px;margin-top:16px;">Sent from LWA Leads Group website</p>
        </div>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
      console.log(`✅ Contact email sent from ${safeEmail} at ${new Date().toISOString()}`);
      res.json({ success: true, message: 'Message sent! We will get back to you soon.' });
    } catch (err) {
      console.error('❌ Contact email failed:', err.message);
      res.status(500).json({ success: false, message: 'Failed to send. Please try again or contact us directly.' });
    }
  }
);

// ─── CATCH-ALL: Serve HTML ────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── ERROR HANDLER ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ success: false, message: 'Access denied.' });
  }
  console.error('Unhandled error:', err.message);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 LWA Backend running on port ${PORT}`);
});
