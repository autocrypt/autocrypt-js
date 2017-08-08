var Autocrypt = require('..')
var setup = require('./util').setup
var test = require('tape')

var bob = 'bob1@example.com'
var alice = 'alice1@example.com'

setup(bob, (bobCrypt, bobKey, doneBob) => {
  setup(alice, (aliceCrypt, aliceKey, doneAlice) => {
    test('generateHeader: generate and process a header three months ago from bob to alice', function (t) {
      bobCrypt.addUser(bob, {public_key: bobKey.publicKey, 'prefer-encrypt': 'mutual'}, function (err) {
        aliceCrypt.addUser(alice, {public_key: aliceKey.publicKey, 'prefer-encrypt': 'mutual'}, function (err) {
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
            var dateSent = new Date()
            dateSent.setMonth(dateSent.getMonth() - 3)
            aliceCrypt.processAutocryptHeader(vals, bob, dateSent, function (err) {
              t.ifError(err)
              t.end()
            })
          })
        })
      })
    })

    test('generateHeader: alice receives new email from bob without autocrypt, recommendation is discourage', function (t) {
      // bob sends alice an email with no autocrypt header
      var dateSent = new Date()
      aliceCrypt.processAutocryptHeader(null, bob, dateSent, function (err, val) {
        t.ok(err, 'Got an error')
        t.ok(err.message.match(/no valid header/), 'no valid header error')
        aliceCrypt.storage.get(bob, function (err, record) {
          t.ifError(err)
          t.ok(record.last_seen_autocrypt < dateSent.getTime() / 1000, 'last_seen_autocrypt is before this one')
          t.same(record.state, 'reset', 'state is reset')
        })
        aliceCrypt.generateHeader(alice, bob, function (err, val) {
          var vals = Autocrypt.parse(val.header)
          t.same(vals.keydata, aliceKey.publicKey, 'bobs public key is in the header')
          t.same(vals.addr, alice, 'email is for alice')
          t.same(vals.type, '1', 'type is 1')
          t.same(vals['prefer-encrypt'], 'mutual')
          t.same(val.recommendation, 'discourage')
          t.end()
        })
      })
    })


    test('generateHeader: cleanup', function (t) {
      doneBob(() => doneAlice(() => t.end()))
    })
  })
})
