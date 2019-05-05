'use strict'

/**
 * Dependencies
 * @ignore
 */
const path = require('path')
const express = require('express')
const bodyParser = require('body-parser')
const session = require('express-session')
const Webauthn = require('webauthn')

/**
 * Module Dependencies
 * @ignore
 */

/**
 * Example
 * @ignore
 */
const app = express()

// Session
app.use(session({
  secret: 'keyboard cat',
  saveUninitialized: true,
  resave: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}))

// Static
app.use(express.static(path.join(__dirname, 'build')))

// Body parsing
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

// Create webauthn
const webauthn = new Webauthn({
  origin: 'https://stranger-webauthn.ngrok.io',
  usernameField: 'username',
  userFields: {
    username: 'username',
    name: 'displayName',
  },
  rpName: 'Stranger Labs, Inc.',
})

// Mount webauthn endpoints
app.use('/webauthn', webauthn.initialize())

// Endpoint without passport
app.get('/secret', webauthn.authenticate(/*{ failureRedirect: '/' }*/), (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Super Secret!' })
})

// Debug
app.get('/db', (req, res) => {
  const data = {}

  webauthn.model.db.createReadStream()
    .on('data', item => data[item.key] = item.value)
    .on('end', () => res.status(200).json(data))
    .on('error', () => res.status(500).json({ status: 'failed' }))
})

// Debug
app.get('/session', (req, res) => {
  res.status(200).json(req.session)
})

// Serve React App
app.use((req, res) => {
  return res.sendFile(path.join(__dirname, 'build', 'index.html'))
})

// Listen
const port = process.env.PORT || 3000
app.listen(port, () => {
  console.log('Listening on port', port)
})
