var setup = require('./util').setup
var test = require('tape')

var fromAddr = 'jon@example.com'

test('processAutocryptHeader: is parsed and user added', function (t) {
  setup(fromAddr, (crypt, key, done) => {
    // Incoming valid email header. Process it and add it to the log.
    var header = {
      keydata: key.publicKeyArmored,
      type: '1',
      'prefer-encrypt': 'mutual',
      'addr': fromAddr
    }
    crypt.processAutocryptHeader(header, fromAddr, new Date(), (err) => {
      t.ifError(err, 'no error')
      crypt.storage.get(fromAddr, (err, record) => {
        t.ifError(err)
        t.same(record.keydata, key.publicKeyArmored, 'public key for incoming mail is stored correctly')
        done(() => t.end())
      })
    })
  })
})

test('processAutocryptHeader: email not same as header.addr', function (t) {
  setup(fromAddr, (crypt, key, done) => {
    var header = {
      keydata: key.publicKeyArmored,
      type: '1',
      'prefer-encrypt': 'mutual',
      'addr': fromAddr
    }
    crypt.processAutocryptHeader(header, 'notthesame@gmail.com', new Date(), (err) => {
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

test('processAutocryptHeader: type 1 is only supported type', function (t) {
  setup(fromAddr, (crypt, key, done) => {
    var header = {
      keydata: key.publicKeyArmored,
      type: '4',
      'prefer-encrypt': 'mutual',
      'addr': fromAddr
    }
    crypt.processAutocryptHeader(header, fromAddr, new Date(), (err) => {
      t.ok(err, 'there should be an error')
      t.same(err.message, 'Invalid Autocrypt Header: the only supported type is 1. Got 4')

      crypt.storage.get(fromAddr, (err, record) => {
        t.ifError(err)
        t.same(record.state, 'reset')
        done(() => t.end())
      })
    })
  })
})
