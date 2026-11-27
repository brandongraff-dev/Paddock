'use strict';
const express = require('express');

const app = express();
const port = Number(process.env.PORT || 3000);
const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) {
  throw new Error('SESSION_SECRET is required');
}

app.disable('x-powered-by');

app.get('/health', (req, res) => {
  res.json({ ok: true });
});

app.listen(port, '127.0.0.1');
