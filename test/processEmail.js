var Autocrypt = require('..')
var MimeBuilder = require('emailjs-mime-builder')
var setup = require('./util').setup
var test = require('tape')

var fromAddr = 'jon@example.com'

test('processEmail: process incoming email header', function (t) {
  setup(fromAddr, (crypt, key, done) => {
    var header = {
      'from': fromAddr,
      'date': new Date().getTime() / 1000,
      'Autocrypt': Autocrypt.stringify({
        keydata: key.publicKeyArmored,
        type: '1',
        'prefer-encrypt': 'mutual',
        'addr': fromAddr
      })
    }

    var mime = new MimeBuilder("text/plain").
      setHeader(header).
      setContent('Hello World!').
      build()

    crypt.processEmail(mime, (err) => {
      t.ifError(err)

      crypt.storage.get(fromAddr, (err, record) => {
        t.ifError(err)
        t.same(record.state, 'mutual')
        t.same(record.addr, fromAddr)
        t.same(record.type, '1')
        t.same(record.keydata, key.publicKeyArmored)
        done(() => t.end())
      })
    })
  })
})

test('processEmail: only one autocrypt header allowed', function (t) {
  setup(fromAddr, (crypt, key, done) => {
    var autocryptHeader = Autocrypt.stringify({
      keydata: key.publicKeyArmored,
      type: '1',
      'prefer-encrypt': 'mutual',
      'addr': fromAddr
    })
    var headers = {
      'from': fromAddr,
      'date': new Date().getTime() / 1000,
    }

    var mime = new MimeBuilder("text/plain").
      setHeader(headers).
      addHeader('Autocrypt', autocryptHeader).
      addHeader('Autocrypt', autocryptHeader).
      setContent('Hello World!').
      build()

    var dateSent = new Date().getTime() / 1000
    crypt.processEmail(mime, (err) => {
      t.ok(err, 'there should be an error')
      t.same(err.message, 'Invalid Autocrypt Header: Only one autocrypt header allowed.')

      crypt.storage.get(fromAddr, (err, record) => {
        t.ok(err, 'no storage entry added for email because too many headers')
        done(() => t.end())
      })
    })
  })
})

test('processEmail: email not same as header.addr', function (t) {
  setup(fromAddr, (crypt, key, done) => {
    var headers = {
      'from': 'notthesame@gmail.com',
      'date': new Date().getTime() / 1000,
      'Autocrypt': Autocrypt.stringify({
        keydata: key.publicKeyArmored,
        type: '1',
        'prefer-encrypt': 'mutual',
        'addr': fromAddr
      })
    }

    var mime = new MimeBuilder("text/plain").
      setHeader(headers).
      setContent('Hello World!').
      build()

    var dateSent = new Date().getTime() / 1000
    crypt.processEmail(mime, (err) => {
      t.ok(err, 'there should be an error')
      t.same(err.message, 'Invalid Autocrypt Header: addr not the same as from email.')

      crypt.storage.get('notthesame@gmail.com', (err, record) => {
        t.ifError(err)
        t.same(record.state, 'reset')
        done(() => t.end())
      })
    })
  })
})


test('processEmail: header.addr not same as email', function (t) {
  setup(fromAddr, (crypt, key, done) => {
    var headers = {
      'from': fromAddr,
      'date': new Date().getTime() / 1000,
      'Autocrypt': Autocrypt.stringify({
        keydata: key.publicKeyArmored,
        type: '1',
        'prefer-encrypt': 'mutual',
        'addr': 'notthesame@gmail.com'
      })
    }

    var mime = new MimeBuilder("text/plain").
      setHeader(headers).
      setContent('Hello World!').
      build()

    var dateSent = new Date().getTime() / 1000
    crypt.processEmail(mime, (err) => {
      t.ok(err, 'there should be an error')
      t.same(err.message, 'Invalid Autocrypt Header: addr not the same as from email.')

      crypt.storage.get(fromAddr, (err, record) => {
        t.ifError(err)
        t.same(record.state, 'reset')
        done(() => t.end())
      })
    })
  })
})
