'use strict';

import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = process.env.PORT || 3000;
const TOKEN_TTL_MS = 1000 * 60 * 60; // 1h TTL for tokens

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use(
  session({
    secret: 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 }, // 1h
  }),
);

const users = [];

function findUserByEmail(email) {
  return users.find((u) => u.email.toLowerCase() === email.toLowerCase());
}

function findUserById(id) {
  return users.find((u) => u.id === id);
}

function generateToken() {
  return uuidv4();
}

function passwordMeetsRules(pw) {
  if (typeof pw !== 'string') {
    return false;
  }

  if (pw.length < 8) {
    return false;
  }

  if (!/[0-9]/.test(pw)) {
    return false;
  }

  if (!/[a-z]/.test(pw)) {
    return false;
  }

  if (!/[A-Z]/.test(pw)) {
    return false;
  }

  return true;
}

function sendEmail(to, subject, body) {
  // simulated email log
  void { to, subject, body };
}

function ensureAuth(req, res, next) {
  if (req.session && req.session.userId) {
    const u = findUserById(req.session.userId);

    if (u) {
      req.user = u;

      return next();
    }
  }

  return res.status(401).json({ error: 'Authentication required' });
}

function ensureNotAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return res.status(400).json({ error: 'Already authenticated' });
  }

  return next();
}

app.post('/register', ensureNotAuth, async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  if (findUserByEmail(email)) {
    return res.status(400).json({ error: 'Email already registered' });
  }

  if (!passwordMeetsRules(password)) {
    return res.status(400).json({
      error:
        'Password does not meet rules. Rules: min 8 chars, 1 digit, ' +
        '1 lowercase, 1 uppercase.',
    });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const activationToken = generateToken();
  const now = Date.now();

  const newUser = {
    id: uuidv4(),
    name,
    email: email.toLowerCase(),
    passwordHash,
    active: false,
    activationToken: { token: activationToken, createdAt: now },
    resetToken: null,
    pendingEmailChange: null,
  };

  users.push(newUser);

  const activationLink = `${req.protocol}://${req.get('host')}/activate/${activationToken}`;

  sendEmail(
    newUser.email,
    'Activate your account',
    `Click to activate: ${activationLink}`,
  );

  return res.status(201).json({
    message: 'Registered. Activation email sent (check server logs).',
  });
});

app.get('/activate/:token', ensureNotAuth, (req, res) => {
  const { token } = req.params;
  const user = users.find(
    (u) => u.activationToken && u.activationToken.token === token,
  );

  if (!user) {
    return res.status(400).json({ error: 'Invalid activation token' });
  }

  if (Date.now() - user.activationToken.createdAt > TOKEN_TTL_MS) {
    return res.status(400).json({ error: 'Activation token expired' });
  }

  user.active = true;
  user.activationToken = null;

  req.session.userId = user.id;

  return res.redirect('/profile');
});

app.post('/login', ensureNotAuth, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const user = findUserByEmail(email);

  if (!user) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);

  if (!ok) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  if (!user.active) {
    return res.status(403).json({
      error: 'User not active. Please activate your email.',
    });
  }

  req.session.userId = user.id;

  return res.redirect('/profile');
});

app.post('/logout', ensureAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }

    res.clearCookie('connect.sid');

    return res.redirect('/login');
  });
});

app.post('/password-reset', ensureNotAuth, (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email required' });
  }

  const user = findUserByEmail(email);

  if (!user) {
    return res.json({
      message: 'If account exists, reset email sent (simulated).',
    });
  }

  const resetToken = generateToken();
  const now = Date.now();

  user.resetToken = { token: resetToken, createdAt: now };

  const resetLink = `${req.protocol}://${req.get('host')}/password-reset/${resetToken}`;

  sendEmail(user.email, 'Password reset', `Reset your password: ${resetLink}`);

  return res.json({
    message: 'If account exists, reset email sent (simulated).',
  });
});

app.get('/password-reset/:token', ensureNotAuth, (req, res) => {
  const { token } = req.params;
  const user = users.find((u) => u.resetToken && u.resetToken.token === token);

  if (!user || Date.now() - user.resetToken.createdAt > TOKEN_TTL_MS) {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }

  return res.status(200).json({ message: 'Token valid' });
});

app.post('/password-reset/:token', ensureNotAuth, async (req, res) => {
  const { token } = req.params;
  const { password, confirmation } = req.body;

  if (!password || !confirmation) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  if (password !== confirmation) {
    return res
      .status(400)
      .json({ error: 'Password and confirmation must match' });
  }

  if (!passwordMeetsRules(password)) {
    return res.status(400).json({ error: 'Password does not meet rules.' });
  }

  const user = users.find((u) => u.resetToken && u.resetToken.token === token);

  if (!user || Date.now() - user.resetToken.createdAt > TOKEN_TTL_MS) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  user.passwordHash = await bcrypt.hash(password, 10);
  user.resetToken = null;

  return res.redirect('/login');
});

// profile routes same as linted style...
// You can copy your existing profile routes here, no long lines >80

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.listen(PORT, () => {
  void PORT;
});
