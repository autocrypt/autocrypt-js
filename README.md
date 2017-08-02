# autocrypt-js
A Node.js implementation of the Autocrypt spec.

## API


## ```Autocrypt(opts)```

Options include:
* `getPGPKeyForEmail = function (emailAddr, function (publicKey, privateKey) {})`
* `storage = {appendUser(headers), updateUser(headers, data), findUser(email)}`

```js
var Autocrypt = require('autocrypt')

// options for internal storage and encryption. comes with some basic defaults
var autocrypt = new Autocrypt(opts)
autocrypt.processHeader(header, email, dateSent, cb)
autocrypt.getPublicKey(email, cb)
autocrypt.generateHeader(fromEmail, toEmail, cb)
```
