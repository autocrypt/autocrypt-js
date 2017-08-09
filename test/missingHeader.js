var Autocrypt = require('..')
var setup = require('./util').setup
var test = require('tape')

var fromAddr = 'pam@example.com'

test('missingHeader: type not present', function (t) {
  var header = {
    'prefer-encrypt': 'mutual',
    'addr': fromAddr
  }
  testMissing(t, header, 'Invalid Autocrypt Header: type is required.')
})

test('missingHeader: keydata not present', function (t) {
  var header = {
    'prefer-encrypt': 'mutual',
    'addr': fromAddr,
    type: '1'
  }
  var errorMsg = 'Invalid Autocrypt Header: keydata is required.'
  setup(fromAddr, (crypt, key, done) => {
    crypt.processAutocryptHeader(header, fromAddr, new Date(), (err) => {
      t.ok(err, 'there should be an error')
      t.same(err && err.message, errorMsg)

      crypt.storage.get(fromAddr, (err, record) => {
        t.ifError(err)
        t.same(record.state, 'reset')
        done(() => t.end())
      })
    })
  })
})

test('missingHeader: prefer-encrypt not present', function (t) {
  var header = {
    'addr': fromAddr,
    type: '1'
  }
  testMissing(t, header, 'Invalid Autocrypt Header: prefer-encrypt is required.')
})

test('missingHeader: addr not present', function (t) {
  var header = {
    'prefer-encrypt': 'mutual',
    type: '1'
  }
  testMissing(t, header, 'Invalid Autocrypt Header: addr is required.')
})

function testMissing (t, header, errorMsg) {
  setup(fromAddr, (crypt, key, done) => {
    header.keydata = key.publicKeyArmored
    crypt.processAutocryptHeader(header, fromAddr, new Date(), (err) => {
      t.ok(err, 'there should be an error')
      t.same(err && err.message, errorMsg)

      crypt.storage.get(fromAddr, (err, record) => {
        t.ifError(err)
        t.same(record.state, 'reset')
        done(() => t.end())
      })
    })
  })
}
