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
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: function(o,cb){ if(!o||( process.env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).includes(o))cb(null,true); else cb(new Error('CORS'),false); }, methods:['GET','POST'], allowedHeaders:['Content-Type'] }));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(__dirname));

const formLimiter = rateLimit({ windowMs: 15*60*1000, max: 5, message: { success: false, message: 'Too many requests.' } });
app.use(rateLimit({ windowMs: 60*1000, max: 60 }));

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_PORT === '465',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  tls: { rejectUnauthorized: false }
});

transporter.verify(err => {
  if (err) console.error('❌ SMTP Error:', err.message);
  else console.log('✅ SMTP ready');
});

function sanitize(str) {
  if (!str) return '';
  return String(str).replace(/</g,'&lt;').replace(/>/g,'&gt;').trim().substring(0,500);
}

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/booking', formLimiter,
  [body('firstName').trim().notEmpty().escape(), body('lastName').trim().notEmpty().escape(), body('email').isEmail().normalizeEmail(), body('date').notEmpty().isISO8601().toDate(), body('time').notEmpty().trim().escape()],
  async (req, res) => {
    if (!validationResult(req).isEmpty()) return res.status(400).json({ success: false, message: 'Invalid data.' });
    const { firstName, lastName, email, date, time } = req.body;
    try {
      await transporter.sendMail({
        from: `"LWA Website" <${process.env.SMTP_USER}>`,
        to: process.env.BUSINESS_EMAIL,
        replyTo: email,
        subject: `📅 New Booking — ${sanitize(firstName)} ${sanitize(lastName)}`,
        html: `<div style="font-family:Arial,sans-serif;padding:30px;background:#f9f9f9"><div style="background:#080c0a;padding:20px;text-align:center;border-radius:8px 8px 0 0"><h2 style="color:#00e87a;margin:0">LWA Leads Group</h2><p style="color:#7a9484;margin:4px 0 0;font-size:13px">New Booking Request</p></div><div style="background:#fff;padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px"><table style="width:100%;border-collapse:collapse"><tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666;width:35%"><strong>Name</strong></td><td style="padding:10px 0;border-bottom:1px solid #f0f0f0">${sanitize(firstName)} ${sanitize(lastName)}</td></tr><tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666"><strong>Email</strong></td><td style="padding:10px 0;border-bottom:1px solid #f0f0f0">${sanitize(email)}</td></tr><tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666"><strong>Date</strong></td><td style="padding:10px 0;border-bottom:1px solid #f0f0f0">${new Date(date).toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'})}</td></tr><tr><td style="padding:10px 0;color:#666"><strong>Time</strong></td><td style="padding:10px 0">${sanitize(time)}</td></tr></table><div style="margin-top:16px;padding:12px;background:#f0fdf4;border-left:3px solid #00e87a"><p style="margin:0;font-size:13px;color:#444">💡 Hit <strong>Reply</strong> to respond directly.</p></div></div></div>`
      });
      res.json({ success: true });
    } catch (err) {
      console.error('❌ Booking failed:', err.message);
      res.status(500).json({ success: false, message: 'Failed to send.' });
    }
  }
);

app.post('/api/contact', formLimiter,
  [body('name').trim().notEmpty().escape(), body('email').isEmail().normalizeEmail(), body('message').trim().notEmpty().isLength({ min:10, max:2000 }).escape()],
  async (req, res) => {
    if (!validationResult(req).isEmpty()) return res.status(400).json({ success: false, message: 'Invalid data.' });
    const { name, email, message } = req.body;
    try {
      await transporter.sendMail({
        from: `"LWA Website" <${process.env.SMTP_USER}>`,
        to: process.env.BUSINESS_EMAIL,
        replyTo: email,
        subject: `✉️ New Message from ${sanitize(name)}`,
        html: `<div style="font-family:Arial,sans-serif;padding:30px;background:#f9f9f9"><div style="background:#080c0a;padding:20px;text-align:center;border-radius:8px 8px 0 0"><h2 style="color:#00e87a;margin:0">LWA Leads Group</h2><p style="color:#7a9484;margin:4px 0 0;font-size:13px">New Contact Message</p></div><div style="background:#fff;padding:24px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px"><table style="width:100%;border-collapse:collapse"><tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666;width:25%"><strong>Name</strong></td><td style="padding:10px 0;border-bottom:1px solid #f0f0f0">${sanitize(name)}</td></tr><tr><td style="padding:10px 0;border-bottom:1px solid #f0f0f0;color:#666"><strong>Email</strong></td><td style="padding:10px 0;border-bottom:1px solid #f0f0f0">${sanitize(email)}</td></tr></table><div style="margin-top:16px"><p style="color:#666;margin-bottom:8px"><strong>Message:</strong></p><div style="background:#f8f8f8;padding:16px;border-radius:4px;border:1px solid #eee;white-space:pre-wrap">${sanitize(message)}</div></div><div style="margin-top:16px;padding:12px;background:#f0fdf4;border-left:3px solid #00e87a"><p style="margin:0;font-size:13px;color:#444">💡 Hit <strong>Reply</strong> to respond directly.</p></div></div></div>`
      });
      res.json({ success: true });
    } catch (err) {
      console.error('❌ Contact failed:', err.message);
      res.status(500).json({ success: false, message: 'Failed to send.' });
    }
  }
);

app.get('*', (req, res) => {
  const p = path.join(__dirname, 'index.html');
  fs.existsSync(p) ? res.sendFile(p) : res.status(404).send('Not found');
});

app.listen(PORT, () => console.log(`🚀 LWA Backend running on port ${PORT}`));
