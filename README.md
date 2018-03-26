# autocrypt-js

A Node.js implementation of the Autocrypt specification.

[![npm][0]][1] [![Travis][2]][3] [![Test coverage][4]][5]


```
npm install autocrypt
```

## API

### ```var autocrypt = new Autocrypt(opts)```

Options include:
* `storage`: the storage to use for internal state. Must implement `get` and `put` methods. (`{get(fromEmail, cb), put(fromEmail, data, cb)}`)
* `dir`: the directory for storing the internal state.

### ```autocrypt.processHeader(header, fromEmail, dateSent, cb)```

Parse the email yourself and pass in the autocrypt header, from email, and date sent.

* `header`: String of the text after `Autocrypt:` or an object with all parsed autocrypt headers.
* `fromEmail`: String.
* `dateSent`: Date object.

### ```autocrypt.processEmail(email, cb)```

Take the full email string (including headers) and parse it using a built-in email parser.

### ```autocrypt.generateAutocryptHeader(fromEmail, cb)```

Generate a string Autocrypt header given the email. `fromEmail` must reference a user that has been added with the `addUser` method.

### ```autocrypt.recommendation(fromEmail, toEmail, cb)```

Generate an autocrypt UI recommendation given the from email and to email. `fromEmail` must reference a user that has been added with the `addUser` method.

### ```autocrypt.addUser(fromEmail, key, opts, cb)```

Add a user to autocrypt. This should be done for all new accounts. `key` should be base64 encoding

* `opts`:
  * `prefer-encrypt`: `mutual` or `nopreference`. Defaults to `nopreference`.

### ```autocrypt.updateUser(fromEmail, opts, cb)```

Update a user in autocrypt. Options are the same as `addUser`.

### ```autocrypt.getUser(fromEmail, cb)```

Get a user who has been added to autocrypt. Returns an error in the callback if no user has been added with that email.


## Static Methods

### ```Autocrypt.stringify(header)```

Turn an object into an Autocrypt MIME string for use in an email header.

```js
var header = Autocrypt.stringify({
  public_key: '---- BEGIN ...',
  addr: 'myemail@myuniversity.edu',
  'prefer-encrypt': 'mutual'
})
```

You can also pass the Autocrypt base-64 encoded `keydata` directly.

```js
var header = Autocrypt.stringify({
  keydata: 'pYEWY0RSAEER1+gQRtZECyyww67....',
  addr: 'myemail@myuniversity.edu',
  'prefer-encrypt': 'mutual'
})
```

A value of `type=1` is automatically added to the header if not supplied, since at this time Autocrypt only supports `type=1`.

### ```Autocrypt.parse(header)```

Turn an Autocrypt MIME string into an object. Opposite of `Autocrypt.stringify`.

```js
var data = Autocrypt.parse('type=1;addr=myemail@myuniversity.edu;prefer-encrypt=mutual;keydata=Li4u;')
```

## License

MIT

[0]: https://img.shields.io/npm/v/autocrypt.svg?style=flat-square
[1]: https://npmjs.org/package/autocrypt
[2]: https://img.shields.io/travis/autocrypt/autocrypt-js/master.svg?style=flat-square
[3]: https://travis-ci.org/karissa/autocrypt-js
[4]: https://img.shields.io/codecov/c/github/autocrypt/autocrypt-js/master.svg?style=flat-square
[5]: https://codecov.io/github/autocrypt/autocrypt-js
