# autocrypt-js

A WIP Node.js implementation of the Autocrypt specification. 

[![Travis](https://travis-ci.org/karissa/autocrypt-js.svg?branch=master)](https://travis-ci.org/autocrypt-js) | [![NPM version](https://img.shields.io/npm/v/autocrypt.svg)](https://npmjs.org/package/autocrypt)


## API

### ```Autocrypt(opts)```

Options include:
* `storage = {get(fromEmail, cb), put(fromEmail, data, cb)}`

```js
var Autocrypt = require('autocrypt')

// options for internal storage and encryption. comes with some basic defaults
var autocrypt = new Autocrypt(opts)
autocrypt.processHeader(header, email, dateSent, cb)
```
