# Simple WebAuthn Example Application

> An example of Stranger Labs&#39; WebAuthn RP usage

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Install

```sh
$ npm i
```

## Usage

1. Install dependencies (as above).
2. Edit the WebAuthn configuration in `server.js`:

```js
const webauthn = new Webauthn({
  origin: 'http://localhost:3000',
  rpName: 'Stranger Labs, Inc.',
  // store: new LevelAdapter(),
  // OR
  // store: {
  //   put: async (id, value) => {/* return <void> */},
  //   get: async (id) => {/* return User */},
  //   search: async (search) => {/* return { [username]: User } */},
  //   delete: async (id) => {/* return boolean */},
  // },
  // ...
})
```

3. Build the react application and run the server:

```sh
$ npm start
```

## Development

For an unoptimized development version, first run the server:

```sh
$ npm run dev-server
```

Then in another terminal, run the react application in development mode:

```sh
$ npm run dev-client
```

## Contributing

Small note: If editing the README, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

MIT © 2019 Stranger Labs, Inc.
