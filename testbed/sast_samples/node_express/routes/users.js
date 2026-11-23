// Users router, mounted at /users in app.js.
const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/', async (req, res) => {
  const { name } = req.query;
  const rows = await db.query(`SELECT * FROM users WHERE name = '${name}'`); // VULN: SQL injection
  res.json(rows);
});

router.get('/:id', (req, res) => {
  db.all("SELECT * FROM users WHERE id = " + req.params.id, (err, rows) => { // VULN: SQL injection (path)
    res.json(rows);
  });
});

module.exports = router;
