# WebAuthn

[![standard-readme compliant](https://img.shields.io/badge/standard--readme-OK-green.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

> W3C Web Authentication API Relying Party for Node.js and Express

WebAuthn is a [W3C standard][w3c] that enables web developers to replace passwords in their applications with [FIDO authentication][fido2]. This repository implements a NPM package for use in Node.js services. **This package is in active development and not yet ready for production use. You can use it to kick the tires on WebAuthn. Please file issues to ask questions or provide feedback.**

[w3c]: https://w3c.github.io/webauthn/
[fido2]: https://fidoalliance.org/fido2/


## Table of Contents

- [Webauthn](#webauthn)
  - [Table of Contents](#table-of-contents)
  - [Security](#security)
  - [Install](#install)
  - [Usage](#usage)
  - [API](#api)
  - [Maintainers](#maintainers)
  - [Contributing](#contributing)
  - [License](#license)

## Security

This package is not yet ready for use in production software. For more information on security considerations see [W3C Web Authentication][w3c-sec] and [FIDO Security Reference][fido-sec].

[w3c-sec]: https://w3c.github.io/webauthn/#security-considerations
[fido-sec]: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-security-ref-v2.0-rd-20180702.html

## Install

```sh
$ npm install webauthn
```

## Usage

See [examples](./examples) for a complete example. The package currently works on its own and we plan to support Passport.js integration in future releases.

```javascript
const Webauthn = require('webauthn')

// configure express and session middleware; see "examples" in this repository
// ...

// Create webauthn
const webauthn = new Webauthn({
  origin: 'https://webauthn.ngrok.io',
  usernameField: 'username',
  userFields: {
    username: 'username',
    name: 'displayName',
  },
  store: new LevelAdapter(),
  // OR
  // store: {
  //   put: async (id, value) => {/* return <void> */},
  //   get: async (id) => {/* return User */},
  //   search: async (search) => {/* return { [username]: User } */},
  //   delete: async (id) => {/* return boolean */},
  // },
  rpName: 'Stranger Labs, Inc.',
})

// Mount webauthn endpoints
app.use('/webauthn', webauthn.initialize())

// Endpoint without passport
app.get('/secret', webauthn.authenticate(), (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Super Secret!' })
})
```

## API

## Maintainers

[@Terrahop](https://github.com/Terrahop)

[@EternalDeiwos](https://github.com/EternalDeiwos)

[@christiansmith](https://github.com/christiansmith)

## Contributing

### Issues

* Please file [issues](https://github.com/strangerlabs/webauthn/issues) :)
* When writing a bug report, include relevant details such as platform, version, relevant data, and stack traces
* Ensure to check for existing issues before opening new ones
* Read the documentation before asking questions
* It is strongly recommended to open an issue before hacking and submitting a PR

### Pull requests

#### Policy

* We're not presently accepting *unsolicited* pull requests
* Create an issue to discuss proposed features before submitting a pull request
* Create an issue to propose changes of code style or introduce new tooling
* Ensure your work is harmonious with the overall direction of the project
* Ensure your work does not duplicate existing effort
* Keep the scope compact; avoid PRs with more than one feature or fix
* Code review with maintainers is required before any merging of pull requests
* New code must respect the style guide and overall architecture of the project
* Be prepared to defend your work

#### Style guide

* [Conventional Changelog](https://github.com/conventional-changelog/conventional-changelog)
* [ECMAScript](https://tc39.github.io/ecma262/)
* [Standard JavaScript](https://standardjs.com)
* [Standard README](https://github.com/RichardLitt/standard-readme)
* [jsdoc](https://jsdoc.app)

#### Code reviews

* required before merging PRs
* reviewers MUST run and test the code under review

### Code of conduct

* @strangerlabs/webauthn follows the [Contributor Covenant](http://contributor-covenant.org/version/1/3/0/) Code of Conduct.

## License

MIT © 2019 Stranger Labs, Inc.
