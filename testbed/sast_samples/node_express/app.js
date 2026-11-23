// Intentionally vulnerable Express app (academic SAST target).
const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');
const escapeHtml = require('escape-html');
const db = require('./db');

const app = express();
app.use('/users', require('./routes/users'));

app.get('/search', (req, res) => {
  const q = req.query.q;
  res.send('<h1>Results for ' + q + '</h1>');                      // VULN: reflected XSS
});

app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out)); // VULN: command injection
});

app.get('/file', (req, res) => {
  fs.readFile('./files/' + req.query.name, 'utf8', (err, data) => { // VULN: path traversal
    res.type('text').send(data);
  });
});

app.get('/go', (req, res) => {
  res.redirect(req.query.next);                                     // VULN: open redirect
});

app.post('/calc', (req, res) => {
  const result = eval(req.body.expr);                               // VULN: code injection
  res.json({ result });
});

app.get('/profile', (req, res) => {
  res.render('profile', { output: { bio: req.query.bio } });        // VULN: XSS via {{{ }}} (Handlebars)
});

app.get('/card', (req, res) => {
  res.render('card', { name: req.query.name });                     // VULN: XSS via != (Pug)
});

// --- safe counterparts -------------------------------------------------------
app.get('/safe/search', (req, res) => {
  res.send(`<h1>Results for ${escapeHtml(req.query.q)}</h1>`);      // escaped -> safe
});

app.get('/safe/user', (req, res) => {
  db.all('SELECT * FROM users WHERE id = ?', [req.query.id], (err, rows) => {
    res.json(rows);                                                 // parameterized -> safe
  });
});

app.get('/safe/echo', (req, res) => {
  res.json({ q: req.query.q });                                     // JSON response -> safe
});

app.get('/safe/profile', (req, res) => {
  res.render('profile_safe', { output: { bio: req.query.bio } });   // {{ }} escapes -> safe
});

app.get('/safe/card', (req, res) => {
  res.render('card_safe', { name: req.query.name });                // = escapes -> safe
});

module.exports = app;
