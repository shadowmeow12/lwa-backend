require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const path = require('path');
const fs = require('fs');

const app = express();

// 🔥 مهم جداً عشان Render بيشتغل خلف Proxy
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));

app.use(cors({
  origin: function (origin, callback) {
    const allowed = (process.env.ALLOWED_ORIGINS || '')
      .split(',')
      .map(x => x.trim());

    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS'), false);
    }
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(__dirname));

/* ===========================
   Rate Limit
=========================== */

const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { success: false, message: 'Too many requests.' }
});

app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60
}));

/* ===========================
   Mail Transport
=========================== */

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_PORT === '465',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  tls: { rejectUnauthorized: false }
});

transporter.verify(err => {
  if (err) console.error('❌ SMTP Error:', err.message);
  else console.log('✅ SMTP ready');
});

/* ===========================
   Helpers
=========================== */

function sanitize(str) {
  if (!str) return '';
  return String(str)
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .trim()
    .substring(0, 500);
}

/* ===========================
   Routes
=========================== */

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

/* ===== Booking ===== */

app.post(
  '/api/booking',
  formLimiter,
  [
    body('firstName').trim().notEmpty().escape(),
    body('lastName').trim().notEmpty().escape(),
    body('email').isEmail().normalizeEmail(),
    body('date').notEmpty().isISO8601().toDate(),
    body('time').notEmpty().trim().escape()
  ],
  async (req, res) => {
    if (!validationResult(req).isEmpty()) {
      return res.status(400).json({ success: false, message: 'Invalid data.' });
    }

    const { firstName, lastName, email, date, time } = req.body;

    try {
      await transporter.sendMail({
        from: `"LWA Website" <${process.env.SMTP_USER}>`,
        to: process.env.BUSINESS_EMAIL,
        replyTo: email,
        subject: `📅 New Booking — ${sanitize(firstName)} ${sanitize(lastName)}`,
        html: `
        <div style="font-family:Arial,sans-serif;padding:30px;background:#f9f9f9">
          <div style="background:#080c0a;padding:20px;text-align:center;border-radius:8px 8px 0 0">
            <h2 style="color:#00e87a;margin:0">LWA Leads Group</h2>
            <p style="color:#7a9484;margin:4px 0 0;font-size:13px">
              New Booking Request
            </p>
          </div>
          <div style="background:#fff;padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px">
            <p><strong>Name:</strong> ${sanitize(firstName)} ${sanitize(lastName)}</p>
            <p><strong>Email:</strong> ${sanitize(email)}</p>
            <p><strong>Date:</strong> ${new Date(date).toLocaleDateString()}</p>
            <p><strong>Time:</strong> ${sanitize(time)}</p>
          </div>
        </div>
        `
      });

      res.json({ success: true });

    } catch (err) {
      console.error('❌ Booking failed:', err.message);
      res.status(500).json({ success: false, message: 'Failed to send.' });
    }
  }
);

/* ===== Contact ===== */

app.post(
  '/api/contact',
  formLimiter,
  [
    body('name').trim().notEmpty().escape(),
    body('email').isEmail().normalizeEmail(),
    body('message')
      .trim()
      .notEmpty()
      .isLength({ min: 10, max: 2000 })
      .escape()
  ],
  async (req, res) => {

    if (!validationResult(req).isEmpty()) {
      return res.status(400).json({ success: false, message: 'Invalid data.' });
    }

    const { name, email, message } = req.body;

    try {
      await transporter.sendMail({
        from: `"LWA Website" <${process.env.SMTP_USER}>`,
        to: process.env.BUSINESS_EMAIL,
        replyTo: email,
        subject: `✉️ New Message from ${sanitize(name)}`,
        html: `
        <div style="font-family:Arial,sans-serif;padding:30px;background:#f9f9f9">
          <div style="background:#080c0a;padding:20px;text-align:center;border-radius:8px 8px 0 0">
            <h2 style="color:#00e87a;margin:0">LWA Leads Group</h2>
          </div>
          <div style="background:#fff;padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px">
            <p><strong>Name:</strong> ${sanitize(name)}</p>
            <p><strong>Email:</strong> ${sanitize(email)}</p>
            <p><strong>Message:</strong></p>
            <div style="background:#f8f8f8;padding:16px;border-radius:4px">
              ${sanitize(message)}
            </div>
          </div>
        </div>
        `
      });

      res.json({ success: true });

    } catch (err) {
      console.error('❌ Contact failed:', err.message);
      res.status(500).json({ success: false, message: 'Failed to send.' });
    }
  }
);

/* ===== Fallback ===== */

app.get('*', (req, res) => {
  const p = path.join(__dirname, 'index.html');
  fs.existsSync(p)
    ? res.sendFile(p)
    : res.status(404).send('Not found');
});

/* ===========================
   Start Server
=========================== */

app.listen(PORT, () => {
  console.log(`🚀 LWA Backend running on port ${PORT}`);
});
