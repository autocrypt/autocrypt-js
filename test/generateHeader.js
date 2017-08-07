var Autocrypt = require('..')
var setup = require('./util').setup
var test = require('tape')

var bob = 'bob@example.com'
var alice = 'alice@example.com'

setup(bob, (bobCrypt, bobKey, doneBob) => {
  setup(alice, (aliceCrypt, aliceKey, doneAlice) => {
    test('generateHeader: generate and process a header from bob to alice', function (t) {
      bobCrypt.storage.put(bob, {keydata: bobKey.publicKey, 'prefer-encrypt': 'mutual'}, function (err) {
        aliceCrypt.storage.put(alice, {keydata: aliceKey.publicKey, 'prefer-encrypt': 'mutual'}, function (err) {
          t.ifError(err)
          // bob sends alice an email
          bobCrypt.generateHeader(bob, alice, function (err, val) {
            t.ifError(err)
            var vals = Autocrypt.parse(val.header)
            t.same(vals.keydata, bobKey.publicKey, 'bobs public key is in the header')
            t.same(vals.addr, bob, 'public key is for bob')
            t.same(vals.type, '1', 'type is 1')
            t.same(vals['prefer-encrypt'], 'mutual')
            t.same(val.recommendation, 'disable')
            // bob sends alice an autocrypt email and she processes it.
            aliceCrypt.processAutocryptHeader(vals, bob, new Date(), function (err) {
              t.ifError(err)
              t.end()
            })
          })
        })
      })
    })

    test('generateHeader: generate a header from alice to bob', function (t) {
      // alice sends bob an email. should have bobs stuff from last time
      aliceCrypt.generateHeader(alice, bob, function (err, val) {
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

    test('generateHeader: alice turns off autocrypt, header is available', function (t) {
      // alice sends bob an email. should have bobs stuff from last time
      aliceCrypt.storage.put(alice, {'prefer-encrypt': 'nopreference'}, function (err) {
        aliceCrypt.generateHeader(alice, bob, function (err, val) {
          t.ifError(err)
          var vals = Autocrypt.parse(val.header)
          t.same(vals.keydata, aliceKey.publicKey, 'bobs public key is in the header')
          t.same(vals.addr, alice, 'public key is for alice')
          t.same(vals.type, '1', 'type is 1')
          t.same(vals['prefer-encrypt'], 'nopreference')
          t.same(val.recommendation, 'available')
          t.end()
        })
      })
    })


    test('generateHeader: cleanup', function (t) {
      doneBob(() => doneAlice(() => t.end()))
    })
  })
})
