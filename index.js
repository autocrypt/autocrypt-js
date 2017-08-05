var debug = require('debug')('autocrypt')
var Mailparser = require('emailjs-mime-parser')
var path = require('path')
var level = require('level')

module.exports = Autocrypt

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
  if (headers['keydata']) ret += `keydata=${new Buffer(headers['keydata']).toString('base64')};`
  return ret
}

/**
 * Parse an autocrypt header
 * @param  {String} header An autocrypt header.
 * @return {Object}        Return all values as an object.
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

Autocrypt.prototype.add = function (email, publicKey, cb) {
  var self = this
  self.storage.put(email, {keydata: publicKey}, cb)
}

Autocrypt.prototype.get = function (email, cb) {
  var self = this
  self.storage.get(email, cb)
}

Autocrypt.recommendation = function (from, to) {
  // TODO: expired public key
  if (!to || to.keydata) return 'disable'
  if (to['state'] === 'mutual' && from['state'] === 'mutual') return 'encrypt'
  if (to['state'] === 'gossip') return 'discourage'
  var oneMonthAgo = new Date();
  oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
  if (to['state'] === 'reset' && to['last_seen_autocrypt'] < oneMonthAgo) return 'discourage'
  return 'available'
}

/**
 * Generate an autocrypt header for given from and to email addresses.
 * This header is meant to be sent from the first email to the second email
 * as the full string after the `Autocrypt:` key in the email header.
 * @param  {String}   fromEmail The email address we are sending the header from.
 * @param  {String}   toEmail   The email address we are sending the header to.
 * @param  {Function} cb        [description]
 */
Autocrypt.prototype.generateHeader = function (fromEmail, toEmail, cb) {
  var self = this
  self.get(fromEmail, function (err, from) {
    if (err) return cb(err)
    self.get(toEmail, function (err, to) {
      if (err && !err.notFound) return cb(err)
      return cb(null, {
        header: Autocrypt.stringify({
          addr: fromEmail,
          type: '1',
          keydata: from.keydata,
          'prefer-encrypt': 'mutual'
        }),
        recommendation: Autocrypt.recommendation(from, to)
      })
    })
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
    var dateSent = node.headers.date[0].value
    var autocryptHeader = node.headers.autocrypt
    if (autocryptHeader.length > 1) return _done(new Error('Invalid Autocrypt Header: Only one autocrypt header allowed.'))
    else autocryptHeader = autocryptHeader[0].initial
    self.processAutocryptHeader(autocryptHeader, fromEmail, dateSent, _done)
  }
  parser.onend = function () {
    cb(error)
  }
  parser.write(email)
}

/**
 * Process an incoming Autocrypt header and add it to the internal log.
 * @param  {Object}   header     The parsed 'Autocrypt' email header.
 * @param  {String}   fromEmail  The email the header was sent from.
 * @param  {Integer}   dateSent  Unix timestamp of date sent.
 * @param  {Function} cb         Callback function
 */
Autocrypt.prototype.processAutocryptHeader = function (header, fromEmail, dateSent, cb) {
  var self = this
  debug('getting record for:', fromEmail)
  if (typeof header === 'string') header = Autocrypt.parse(header)
  debug('header is', header)
  self.storage.get(fromEmail, function (err, record) {
    if (err && !err.notFound) return _done(err)
    if (record && (dateSent < record.last_seen_autocrypt)) return _done()
    debug('got record for:', fromEmail, record)

    var error
    if (!header) error = new Error('Invalid Autocrypt Header: no valid header found')
    if (header.addr !== fromEmail) error = new Error('Invalid Autocrypt Header: addr not the same as from email.')
    if (header.addr !== fromEmail) error = new Error('Invalid Autocrypt Header: addr not the same as from email.')
    if (header.type !== '1') error = new Error(`Invalid Autocrypt Header: the only supported type is 1. Got ${header.type}`)
    if (error) {
      debug('got an error', error)
      return self.storage.put(fromEmail, {last_seen: dateSent, state: 'reset'}, _done)
    }

    var updatedRecord = {
      last_seen: dateSent,
      last_seen_autocrypt: dateSent,
      keydata: header.keydata,
      state: header['prefer-encrypt'] === 'mutual' ? 'mutual' : 'nopreference',
      fpr: header.fpr,
      type: '1',
      addr: header.addr
    }

    debug('updating record:', fromEmail, updatedRecord)
    // when valid
    self.storage.put(fromEmail, updatedRecord, _done)

    function _done (err) {
      if (err) return cb(err)
      return cb(error)
    }
  })
}

function defaultStorage (dir) {
  return level(dir || path.join(__dirname, 'autocrypt-data'), {valueEncoding: 'json'})
}
