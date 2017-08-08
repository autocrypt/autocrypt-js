# autocrypt-js

A WIP Node.js implementation of the Autocrypt specification.

[![Travis](https://travis-ci.org/karissa/autocrypt-js.svg?branch=master)](https://travis-ci.org/karissa/autocrypt-js) | [![NPM version](https://img.shields.io/npm/v/autocrypt.svg)](https://npmjs.org/package/autocrypt)


## API

### ```Autocrypt(opts)```

Options include:
* `storage`: the storage to use for internal state. Must implement `get` and `put` methods. (example: `{get(fromEmail, cb), put(fromEmail, data, cb)}`)
* `dir`: the directory for storing the internal state.

```js
var Autocrypt = require('autocrypt')

// options for internal storage and encryption. comes with some basic defaults
var autocrypt = new Autocrypt(opts)
```

### ```autocrypt.processHeader(header, fromEmail, dateSent, cb)```

Parse the email yourself and pass in the autocrypt header, from email, and date sent.

* `header`: String of the text after `Autocrypt:` or an object with all parsed autocrypt headers.
* `fromEmail`: String.
* `dateSent`: Date object.

### ```autocrypt.processEmail(email, cb)```

Take the full email string (including headers) and parse it using a built-in email parser.

### ```autocrypt.generateHeader(fromEmail, toEmail, cb)```

Generate an autocrypt header given the from email and to email. `fromEmail` must reference a user that has been added with the `addUser` method.

### ```autocrypt.addUser(fromEmail, opts, cb)```

Add a user to autocrypt. This should be done for all new accounts.

* `opts`:
  * `public_key`: Required. The raw public key data for the given user. (`---- BEGIN ...`)
  * `prefer-encrypt`: `mutual` or `nopreference`. Defaults to `nopreference`.

### ```autocrypt.updateUser(fromEmail, opts, cb)```

Update a user in autocrypt. Options are the same as `addUser`.

## Static Methods

### ```Autocrypt.stringify(header)```

Turn an object into an Autocrypt MIME string for use in an email header.

```js
var header = Autocrypt.stringify({
  keydata: '...',
  type: '1',
  addr: 'myemail@myuniversity.edu',
  'prefer-encrypt': 'mutual'
})
```

### ```Autocrypt.parse(header)```

Turn an Autocrypt MIME string into an object. Opposite of `Autocrypt.stringify`.

```js
var data = Autocrypt.parse('type=1;addr=myemail@myuniversity.edu;prefer-encrypt=mutual;keydata=Li4u;')
```
