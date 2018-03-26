var openpgp = require('openpgp')
var autocrypt = require('..')
var memdb = require('memdb')

module.exports = {
  setup: function (fromAddr, cb) {
    var crypt = autocrypt({storage: memdb({valueEncoding: 'json'})})
    openpgp.initWorker({ path: 'openpgp.worker.js' }) // set the relative web worker path
    openpgp.config.aead_protect = true // activate fast AES-GCM mode (not yet OpenPGP standard)

    openpgp.generateKey({
      userIds: [{ name: 'Jon Smith', email: fromAddr }],
      numBits: 1096,
      passphrase: 'super long and hard to guess'
    }
    ).then((key) => cb(crypt, key, done)
    ).catch((err) => { throw err })

    function done (cb) {
      crypt.storage.close(cb)
    }
  }
}
