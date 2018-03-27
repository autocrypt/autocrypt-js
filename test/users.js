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
        t.same(user.keydata, key, 'has keydata')
        t.same(user['prefer-encrypt'], undefined, 'nopreference is default')
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
        t.same(user.keydata, key, 'has keydata')
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
          t.same(user.keydata, key, 'has keydata')
          t.same(user['prefer-encrypt'], 'mutual', 'default is overriden')
          done(() => t.end())
        })
      })
    })
  })
})

test('users: create a user with private key', function (t) {
  setup(email, (crypt, key, done) => {
    crypt.createUser(email, {publicKey: key, privateKey: 'something'}, (err) => {
      t.ifError(err)
      crypt.getUser(email, (err, user) => {
        t.ifError(err)
        t.same(user.keydata, key, 'has keydata')
        t.same(user.privateKey, 'something', 'has privateKey')
        done(() => t.end())
      })
    })
  })
})

test('users: create a user with private key, then add the user later to update something', function (t) {
  setup(email, (crypt, key, done) => {
    crypt.createUser(email, {publicKey: key, privateKey: 'something'}, (err) => {
      t.ifError(err)
      crypt.addUser(email, key, {privateKey: 'foo'}, (err, user) => {
        t.ifError(err)
        crypt.getUser(email, (err, user) => {
          t.ifError(err)
          t.same(user.keydata, key, 'has keydata')
          t.same(user.privateKey, 'something', 'same privateKey as before')
          done(() => t.end())
        })
      })
    })
  })
})
