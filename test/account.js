var autocrypt = require('..')
var openpgp = require('openpgp')
var test = require('tape')

var email = 'hello@xyz.net'

test('throw error if account does not exist', function (t) {
  crypt.getAccount(email, (err, account) => {
    t.ok(err)
  })
})
