var setup = require('./util').setup
var test = require('tape')

var email = 'hello@xyz.net'

test('throw error if account does not exist', function (t) {
  setup(email, (crypt, key, done) => {
    crypt.storage.get(email, (err, account) => {
      t.ok(err)
      done(() => t.end())
    })
  })
})
