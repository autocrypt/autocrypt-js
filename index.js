module.exports = Autocrypt

function Autocrypt (opts) {
  if (!this instanceof Autocrypt) return new Autocrypt(opts)
  this.storage = opts.storage || defaultStorage()

}

/**
 * Process an incoming Autocrypt header and add it to the internal log.
 * @param  {Object}   header     The parsed 'Autocrypt' email header.
 * @param  {String}   fromEmail  The email the header was sent from.
 * @param  {Integer}   dateSent  Unix timestamp of date sent.
 * @param  {Function} cb         Callback function
 */
Autocrypt.prototype.processHeader = function (header, fromEmail, dateSent, cb) {
  this.storage.get(fromEmail, function (err, record) {
    if (err) return _done(err)
    if (dateSent < record.last_seen_autocrypt) return _done()

    var error
    if (header.addr !== fromEmail) error = new Error('Invalid Autocrypt Header: addr not the same as sent email address.')
    if (header.type !== '1') error = new Error('Invalid Autocrypt Header: the only supported "type" is 1.')
    if (error) this.storage.put(fromEmail, {last_seen: dateSent, state: 'reset'}, _done)

    var updatedRecord = {
      last_seen: dateSent,
      last_seen_autocrypt: dateSent,
      keydata: header.keydata,
      state: header['prefer-encrypt'] === 'mutual' ? 'mutual' : 'nopreference',
      fpr: header.fpr,
      type: '1'
    }

    // when valid
    this.storage.put(fromEmail, updatedRecord, _done)

    function _done (err) {
      if (err) return cb(err)
      return cb(error)
    }

  })

}
