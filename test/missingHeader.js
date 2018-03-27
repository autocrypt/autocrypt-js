var setup = require('./util').setup
var test = require('tape')

var fromAddr = 'pam@example.com'

test('missingHeader: keydata not present', function (t) {
  var header = {
    'prefer-encrypt': 'mutual',
    addr: fromAddr
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

test('missingHeader: addr not present', function (t) {
  var header = {
    'prefer-encrypt': 'mutual'
  }
  testMissing(t, header, 'Invalid Autocrypt Header: addr is required.')
})

function testMissing (t, header, errorMsg) {
  setup(fromAddr, (crypt, key, done) => {
    header.keydata = key
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
