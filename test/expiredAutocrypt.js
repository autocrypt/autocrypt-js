var Autocrypt = require('..')
var setup = require('./util').setup
var test = require('tape')

var bob = 'bob1@example.com'
var alice = 'alice1@example.com'

setup(bob, (bobCrypt, bobKey, doneBob) => {
  setup(alice, (aliceCrypt, aliceKey, doneAlice) => {
    test('expiredAutocrypt: generate and process a header three months ago from bob to alice', function (t) {
      bobCrypt.addUser(bob, bobKey.publicKeyArmored, {'prefer-encrypt': 'mutual'}, function (err) {
        t.ifError(err)
        aliceCrypt.addUser(alice, aliceKey.publicKeyArmored, {'prefer-encrypt': 'mutual'}, function (err) {
          t.ifError(err)
          // bob sends alice an email
          bobCrypt.generateAutocryptHeader(bob, function (err, header) {
            t.ifError(err)
            var vals = Autocrypt.parse(header)
            t.same(vals.keydata, Autocrypt.encodeKeydata(bobKey.publicKeyArmored), 'bobs public key is in the header')
            t.same(vals.addr, bob, 'public key is for bob')
            t.same(vals.type, '1', 'type is 1')
            t.same(vals['prefer-encrypt'], 'mutual')
            bobCrypt.recommendation(bob, alice, function (err, recommendation) {
              t.ifError(err)
              t.same(recommendation, 'disable', 'recommendation is disable')
              // bob sends alice an autocrypt email and she processes it.
              var dateSent = new Date()
              dateSent.setMonth(dateSent.getMonth() - 3)
              aliceCrypt.processAutocryptHeader(vals, bob, dateSent, function (err) {
                t.ifError(err, 'no error processing')
                t.end()
              })
            })
          })
        })
      })
    })

    test('expiredAutocrypt: alice receives new email from bob without autocrypt, recommendation is discourage', function (t) {
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
        aliceCrypt.generateAutocryptHeader(alice, function (err, header) {
          t.ifError(err)
          var vals = Autocrypt.parse(header)
          t.same(vals.keydata, Autocrypt.encodeKeydata(aliceKey.publicKeyArmored), 'bobs public key is in the header')
          t.same(vals.addr, alice, 'email is for alice')
          t.same(vals.type, '1', 'type is 1')
          t.same(vals['prefer-encrypt'], 'mutual')
          aliceCrypt.recommendation(alice, bob, function (err, recommendation) {
            t.ifError(err)
            t.same(recommendation, 'discourage')
            t.end()
          })
        })
      })
    })

    test('expiredAutocrypt: cleanup', function (t) {
      doneBob(() => doneAlice(() => t.end()))
    })
  })
})
