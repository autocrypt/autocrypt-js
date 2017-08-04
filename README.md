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
autocrypt.processHeader(header, email, dateSent, cb)
```

### ```autocrypt.processHeader(header, fromEmail, dateSent, cb)```

### ```autocrypt.processEmail(email, cb)```

## Static Methods
### ```Autocrypt.stringify(header)```

Turn an object into an Autocrypt MIME string for use in an email header.

```js
Autocrypt.stringify({
  keydata: '...',
  type: '1',
  addr: 'myemail@myuniversity.edu',
  'prefer-encrypt': 'mutual'
})
```

returns:

```js
'type=1;addr=myemail@myuniversity.edu;prefer-encrypt=mutual;keydata=Li4u;'
```

### ```Autocrypt.parse(header)```

Turn an Autocrypt MIME string into an object. Opposite of `Autocrypt.stringify`.
