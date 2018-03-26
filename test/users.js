var setup = require('./util').setup
var test = require('tape')

var email = 'hello@xyz.net'

test('users: throw error if account does not exist', function (t) {
  setup(email, (crypt, key, done) => {
    crypt.getUser(email, (err, account) => {
      t.ok(err)
      done(() => t.end())
    })
  })
})

test('users: add a user with a null public key', function (t) {
  setup(email, (crypt, key, done) => {
    crypt.addUser(email, null, (err, account) => {
      t.ok(err)
      done(() => t.end())
    })
  })
})

test('users: add and get a user with a public key has defaults', function (t) {
  setup(email, (crypt, key, done) => {
    crypt.addUser(email, key, (err) => {
      t.ifError(err)
      crypt.getUser(email, (err, user) => {
        t.ifError(err)
        t.same(user.public_key, key, 'has public_key')
        t.same(user['prefer-encrypt'], 'nopreference', 'nopreference is default')
        done(() => t.end())
      })
    })
  })
})

test('users: add and get a user with overrided default prefer-encrypt', function (t) {
  setup(email, (crypt, key, done) => {
    crypt.addUser(email, key, {'prefer-encrypt': 'mutual'}, (err) => {
      t.ifError(err)
      crypt.getUser(email, (err, user) => {
        t.ifError(err)
        t.same(user.public_key, key, 'has public_key')
        t.same(user['prefer-encrypt'], 'mutual', 'default is overriden')
        done(() => t.end())
      })
    })
  })
})

test('users: add and update a user', function (t) {
  setup(email, (crypt, key, done) => {
    crypt.addUser(email, key, (err) => {
      t.ifError(err)
      crypt.updateUser(email, {'prefer-encrypt': 'mutual'}, (err) => {
        t.ifError(err)
        crypt.getUser(email, (err, user) => {
          t.ifError(err)
          t.same(user.public_key, key, 'has public_key')
          t.same(user['prefer-encrypt'], 'mutual', 'default is overriden')
          done(() => t.end())
        })
      })
    })
  })
})
