var openpgp = require('openpgp')
var base64 = require('base64-js')
var xtend = require('xtend')
var debug = require('debug')('autocrypt')
var Mailparser = require('emailjs-mime-parser')
var path = require('path')
var level = require('level')

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
  this.storage = opts.storage || defaultStorage(opts.dir)
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
  if (headers.keydata) ret += `keydata=${Buffer.from(headers.keydata).toString('base64')};`
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
  var parts = header.split(';')
  var ret = {}
  parts.forEach(function (part) {
    var breakpoint = part.indexOf('=')
    var key = part.substring(0, breakpoint)
    var value = part.substring(breakpoint + 1)
    ret[key] = value
  })
  if (ret.keydata) ret.keydata = Buffer.from(ret.keydata, 'base64').toString()
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
 * Add a user to the autocrypt.
 * @param {String}   fromEmail The email address.
 * @param {Object}   data      The data for the email address. `public_key` required.
 * @param {Function} cb        Will return an error or nothing if successful.
 */
Autocrypt.prototype.addUser = function (fromEmail, data, cb) {
  var self = this
  var defaults = {
    'prefer-encrypt': 'nopreference'
  }
  self.storage.put(fromEmail, xtend(defaults, data), cb)
}

/**
 * Update an autocrypt user.
 * @param  {String}   fromEmail The email address.
 * @param  {Object}   data      The data for the email address.
 * @param  {Function} cb        Will return an error or nothing if successful.
 */
Autocrypt.prototype.updateUser = function (fromEmail, data, cb) {
  var self = this
  self.storage.get(fromEmail, function (err, user) {
    if (err) return cb(err)
    self.storage.put(fromEmail, xtend(user, data), cb)
  })
}

Autocrypt.encodeKeydata = function (publicKey) {
  return base64.fromByteArray(openpgp.armor.decode(publicKey).data)
}

/**
 * Generate an autocrypt header for given from and to email addresses.
 * This header is meant to be sent from the first email to the second email
 * as the full string after the `Autocrypt:` key in the email header.
 * @param  {String}   fromEmail The email address we are sending the header from.
 * @param  {String}   toEmail   The email address we are sending the header to.
 * @param  {Function} cb        [description]
 */
Autocrypt.prototype.generateAutocryptHeader = function (fromEmail, cb) {
  var self = this
  self.storage.get(fromEmail, function (err, from) {
    if (err) return cb(err)
    cb(null, Autocrypt.stringify({
      addr: fromEmail,
      type: '1',
      keydata: Autocrypt.encodeKeydata(from.public_key),
      'prefer-encrypt': from['prefer-encrypt']
    }))
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
  debug('header is', header)
  self.storage.get(fromEmail, function (err, record) {
    if (err && !err.notFound) return cb(err)
    if (record && (dateSent < record.last_seen_autocrypt)) return cb()
    debug('got record for:', fromEmail, record)

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

function defaultStorage (dir) {
  return level(dir || path.join(__dirname, 'autocrypt-data'), {valueEncoding: 'json'})
}
