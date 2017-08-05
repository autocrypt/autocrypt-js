var Autocrypt = require('..')
var setup = require('./util').setup
var test = require('tape')

var bob = 'bob@example.com'
var alice = 'alice@example.com'

setup(bob, (crypt, bobKey, doneBob) => {
  setup(alice, (crypt, aliceKey, doneAlice) => {
    test('generateHeader: generate a header from bob to alice', function (t) {
      crypt.add(bob, bobKey.publicKey, function (err) {
        t.ifError(err)
        // bob sends alice an email
        crypt.generateHeader(bob, alice, function (err, val) {
          t.ifError(err)
          var vals = Autocrypt.parse(val.header)
          t.same(vals.keydata, bobKey.publicKey, 'bobs public key is in the header')
          t.same(vals.addr, bob, 'public key is for bob')
          t.same(vals.type, '1', 'type is 1')
          t.same(vals['prefer-encrypt'], 'mutual')
          t.same(val.recommendation, 'disable')
          t.end()
        })
      })
    })

    test('generateHeader: generate a header from alice to bob', function (t) {
      crypt.add(alice, aliceKey.publicKey, function (err) {
        t.ifError(err)
        // bob sends alice an email
        crypt.generateHeader(alice, bob, function (err, val) {
          t.ifError(err)
          var vals = Autocrypt.parse(val.header)
          t.same(vals.keydata, aliceKey.publicKey, 'bobs public key is in the header')
          t.same(vals.addr, alice, 'public key is for alice')
          t.same(vals.type, '1', 'type is 1')
          t.same(vals['prefer-encrypt'], 'mutual')
          t.same(val.recommendation, 'encrypt')
          t.end()
        })
      })
    })

    test('generateHeader: cleanup', function (t) {
      doneBob(() => doneAlice(() => t.end()))
    })
  })
})
