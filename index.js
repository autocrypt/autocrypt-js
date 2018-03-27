var xtend = require('xtend')
var debug = require('debug')('autocrypt')
var Mailparser = require('emailjs-mime-parser')

module.exports = Autocrypt

/**
 * A Node.js implementation of the Autocrypt specification.
 * @class
 * @name Autocrypt
 * @param {Object} opts Options object
 */
function Autocrypt (opts) {
  if (!(this instanceof Autocrypt)) return new Autocrypt(opts)
  if (!opts) opts = {}
  if (!opts.storage) throw new Error('opts.storage required')
  this.storage = opts.storage
}

/**
 * Turn an object into a string representation of autocrypt headers.
 * @param  {Object} headers The headers to add.
 * @return {String}         A String representation of the headers to add to an email mime header.
 */
Autocrypt.stringify = function (headers) {
  var ret = ''
  for (var key in headers) {
    if (key === 'keydata') continue
    var value = headers[key]
    ret += `${key}=${value};`
  }
  if (!headers.type) ret += `type=1;`
  if (headers.public_key) ret += `keydata=${headers.public_key};`
  else if (headers.keydata) ret += `keydata=${headers.keydata};`
  else throw new Error('Either an ASCI-armored OpenPGP public_key or base64-encoded Autocrypt keydata field required.')
  return ret
}

/**
 *  Turn an Autocrypt MIME string into an object. Opposite of `Autocrypt.stringify`.
 * @example
 * var data = Autocrypt.parse('type=1;addr=myemail@myuniversity.edu;prefer-encrypt=mutual;keydata=Li4u;')
 * @param  {String}   header  An autocrypt header.
 * @return {Object}           Return values as an object.
 */
Autocrypt.parse = function (header) {
  header = header.replace(/\s+/g, '')
  var parts = header.split(';')
  var ret = {}
  parts.forEach(function (part) {
    var breakpoint = part.indexOf('=')
    var key = part.substring(0, breakpoint)
    var value = part.substring(breakpoint + 1)
    ret[key] = value
  })
  return ret
}

/**
 * Get the recommendation when emailing from one user to another.
 * @param  {String}   fromEmail The from email address.. Must be a user added with `addUser`.
 * @param  {String}   toEmail   The email address we are sending to.
 * @param  {Function} cb        Callback will return the recommendation, one of `available`, `discourage`, `disable` , or `encrypt`
 */
Autocrypt.prototype.recommendation = function (fromEmail, toEmail, cb) {
  var self = this
  self.storage.get(fromEmail, function (err, from) {
    if (err) return cb(err)
    self.storage.get(toEmail, function (err, to) {
      if (err && !err.notFound) return cb(err)
      var ret = 'available'
      if (!to || !to.keydata) ret = 'disable'
      else if (to.state === 'mutual' && from['prefer-encrypt'] === 'mutual') ret = 'encrypt'
      else if (to.state === 'gossip') ret = 'discourage'
      else {
        var oneMonthAgo = new Date()
        oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1)
        if (to.state === 'reset' && to.last_seen_autocrypt < oneMonthAgo.getTime() / 1000) ret = 'discourage'
      }
      cb(null, ret)
    })
  })
}

/**
 * Get a user from autocrypt.
 * @param {String}   fromEmail The email address.
 * @param {Function} cb        Will return an error or the user.
 */
Autocrypt.prototype.getUser = function (fromEmail, cb) {
  this.storage.get(fromEmail, cb)
}

/**
 * Add a user to autocrypt.
 * @param {String}   fromEmail The email address.
 * @param {String}   publicKey The public key associated with the email.
 * @param {Object}   opts      Options for the email address.
 * @param {Function} cb        Returns an error if there is a failure.
 */
Autocrypt.prototype.addUser = function (fromEmail, publicKey, opts, cb) {
  var self = this
  if (!cb && (typeof opts === 'function')) return self.addUser(fromEmail, publicKey, null, opts)
  if (!publicKey || (typeof publicKey !== 'string')) return cb(new Error('publicKey required.'))
  var defaults = {
    public_key: publicKey
  }
  self.storage.put(fromEmail, xtend(defaults, opts), cb)
}

/**
 * Update an autocrypt user.
 * @param  {String}   fromEmail The email address.
 * @param  {Object}   data      The data for the email address to be updated.
 * @param  {Function} cb        Will return an error or nothing if successful.
 */
Autocrypt.prototype.updateUser = function (fromEmail, data, cb) {
  var self = this
  self.storage.get(fromEmail, function (err, user) {
    if (err) return cb(err)
    self.storage.put(fromEmail, xtend(user, data), cb)
  })
}

/**
 * Generate an autocrypt header for given from and to email addresses.
 * This header is meant to be sent from the first email to the second email
 * as the full string after the `Autocrypt:` key in the email header.
 * @param  {String}   fromEmail The email address we are sending the header from.
 * @param  {Function} cb        [description]
 */
Autocrypt.prototype.generateAutocryptHeader = function (fromEmail, cb) {
  var self = this
  self.storage.get(fromEmail, function (err, from) {
    if (err) return cb(err)
    var opts = {
      addr: fromEmail,
      type: '1',
      keydata: from.public_key
    }
    if (from['prefer-encrypt'] === 'mutual') {
      opts['prefer-encrypt'] = 'mutual'
    }
    cb(null, Autocrypt.stringify(opts))
  })
}

/**
 * Process an incoming email string, process the autocrypt headers and give information.
 * @param  {String}   email An incoming email string with all headers, including date, from, and to.
 * @param  {Function} cb    Callback
 */
Autocrypt.prototype.processEmail = function (email, cb) {
  var self = this
  var parser = new Mailparser()
  var error

  function _done (err) {
    error = err
    parser.end()
  }

  parser.onheader = function (node) {
    if (!node.headers.from || !node.headers.date) return _done(new Error('No from and date field, is that expected behavior?'))
    var fromEmail = node.headers.from[0].initial // TODO: should check value. what happens if from two people?
    var dateSent = new Date(node.headers.date[0].value)
    var autocryptHeader = node.headers.autocrypt
    if (autocryptHeader.length > 1) return _done(new Error('Invalid Autocrypt Header: Only one autocrypt header allowed.'))
    else autocryptHeader = autocryptHeader ? autocryptHeader[0].initial : null
    self.processAutocryptHeader(autocryptHeader, fromEmail, dateSent, _done)
  }
  parser.onend = function () {
    cb(error)
  }
  parser.write(email)
}

Autocrypt.prototype.validateHeaderValues = function (fromEmail, header) {
  if (!header) return new Error('Invalid Autocrypt Header: no valid header found')
  var CRITICAL = ['keydata', 'addr', 'type', 'prefer-encrypt']
  for (var i in CRITICAL) {
    var c = CRITICAL[i]
    var msg = `Invalid Autocrypt Header: ${c} is required.`
    if (!header[c]) return new Error(msg)
  }
  if (header.addr !== fromEmail) return new Error('Invalid Autocrypt Header: addr not the same as from email.')
  if (header.type && header.type.toString() !== '1') return new Error(`Invalid Autocrypt Header: the only supported type is 1. Got ${header.type}`)
}

/**
 * Process an incoming Autocrypt header and add it to the internal log.
 * @param  {Object}   header     The parsed 'Autocrypt' email header.
 * @param  {String}   fromEmail  The email the header was sent from.
 * @param  {DateTime}   dateSent  JavaScript Date object of date sent.
 * @param  {Function} cb         Callback function
 */
Autocrypt.prototype.processAutocryptHeader = function (header, fromEmail, dateSent, cb) {
  var self = this
  debug('getting record for:', fromEmail)
  var timestamp = dateSent.getTime() / 1000
  if (header && typeof header === 'string') header = Autocrypt.parse(header)
  dateSent = Math.min(dateSent, Date.now())
  debug('header is', header)
  self.storage.get(fromEmail, function (err, record) {
    if (err && !err.notFound) return cb(err)
    debug('got record for:', fromEmail, record)
    if (record && (dateSent < record.last_seen_autocrypt)) return cb()

    var error = self.validateHeaderValues(fromEmail, header)
    if (error) return _onerror(error)

    function _onerror (error) {
      debug('got an error', error)
      var data = xtend(record, {last_seen: timestamp, state: 'reset'})
      return self.storage.put(fromEmail, data, function (err) {
        if (err) error = err
        return cb(error)
      })
    }

    var updatedRecord = {
      last_seen: timestamp,
      last_seen_autocrypt: timestamp,
      keydata: header.keydata,
      state: header['prefer-encrypt'] === 'mutual' ? 'mutual' : 'nopreference',
      fpr: header.fpr,
      type: '1',
      addr: header.addr
    }

    debug('updating record:', fromEmail, updatedRecord)
    // when valid
    self.storage.put(fromEmail, updatedRecord, cb)
  })
}
