'use strict';

import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

const app = express();
const PORT = process.env.PORT || 3000;

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
  const newUser = {
    id: uuidv4(),
    name,
    email: email.toLowerCase(),
    passwordHash,
    active: false,
    activationToken,
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
  const user = users.find((u) => u.activationToken === token);

  if (!user) {
    return res.status(400).json({ error: 'Invalid activation token' });
  }

  user.active = true;
  user.activationToken = null;

  req.session.userId = user.id;

  return res.json({
    message: 'Account activated. Redirecting to profile...',
    profileUrl: '/profile',
  });
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

  return res.json({ message: 'Logged in', profileUrl: '/profile' });
});

app.post('/logout', ensureAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      // TODO: handle session destroy error
    }

    res.clearCookie('connect.sid');

    return res.json({ message: 'Logged out', loginUrl: '/login' });
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

  user.resetToken = resetToken;

  const resetLink = `${req.protocol}://${req.get('host')}/password-reset/${resetToken}`;

  sendEmail(user.email, 'Password reset', `Reset your password: ${resetLink}`);

  return res.json({
    message: 'If account exists, reset email sent (simulated).',
  });
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

  const user = users.find((u) => u.resetToken === token);

  if (!user) {
    return res.status(400).json({ error: 'Invalid reset token' });
  }

  user.passwordHash = await bcrypt.hash(password, 10);
  user.resetToken = null;

  return res.json({
    message: 'Password reset success. You can now login.',
    loginUrl: '/login',
  });
});

app.get('/profile', ensureAuth, (req, res) => {
  const u = req.user;

  return res.json({
    id: u.id,
    name: u.name,
    email: u.email,
    active: u.active,
  });
});

app.post('/profile/name', ensureAuth, (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Name required' });
  }

  req.user.name = name;

  return res.json({
    message: 'Name updated',
    profile: { name: req.user.name },
  });
});

app.post('/profile/password', ensureAuth, async (req, res) => {
  const { oldPassword, newPassword, confirmation } = req.body;

  if (!oldPassword || !newPassword || !confirmation) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  if (newPassword !== confirmation) {
    return res.status(400).json({
      error: 'New password and confirmation must match',
    });
  }

  if (!passwordMeetsRules(newPassword)) {
    return res.status(400).json({ error: 'New password does not meet rules' });
  }

  const ok = await bcrypt.compare(oldPassword, req.user.passwordHash);

  if (!ok) {
    return res.status(400).json({ error: 'Old password incorrect' });
  }

  req.user.passwordHash = await bcrypt.hash(newPassword, 10);

  return res.json({ message: 'Password changed' });
});

app.post('/profile/email', ensureAuth, (req, res) => {
  const { password, newEmail } = req.body;

  if (!password || !newEmail) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  bcrypt
    .compare(password, req.user.passwordHash)
    .then((ok) => {
      if (!ok) {
        return res.status(400).json({ error: 'Password incorrect' });
      }

      const confirmToken = generateToken();

      req.user.pendingEmailChange = {
        newEmail: newEmail.toLowerCase(),
        confirmToken,
      };

      sendEmail(
        req.user.email,
        'Email change requested',
        `A change to ${newEmail} was requested.`,
      );

      const confirmLink =
        `${req.protocol}://${req.get('host')}/profile/email/confirm/` +
        confirmToken;

      sendEmail(
        newEmail,
        'Confirm your new email',
        `Click to confirm new email: ${confirmLink}`,
      );

      return res.json({
        message:
          'Confirmation email sent to new address (simulated). ' +
          'Old email was notified.',
      });
    })
    .catch(() => {
      // TODO: handle bcrypt error
      return res.status(500).json({ error: 'Server error' });
    });
});

app.get('/profile/email/confirm/:token', (req, res) => {
  const { token } = req.params;
  const user = users.find(
    (u) => u.pendingEmailChange && u.pendingEmailChange.confirmToken === token,
  );

  if (!user) {
    return res.status(400).json({ error: 'Invalid token' });
  }

  const oldEmail = user.email;

  user.email = user.pendingEmailChange.newEmail;
  user.pendingEmailChange = null;

  sendEmail(
    oldEmail,
    'Your email was changed',
    `Your account email was changed to ${user.email}`,
  );

  if (req.session) {
    req.session.userId = user.id;
  }

  return res.json({
    message: 'Email changed. You are redirected to profile.',
    profileUrl: '/profile',
  });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.listen(PORT, () => {
  // server started
  void PORT;
});
