let assert = require('assert')
let sinon = require('sinon')

let express = require('express')

let Webauthn = require('../src/Webauthn')
let MemoryAdapter = require('../src/MemoryAdapter')
let Dictionaries = require('../src/Dictionaries')

describe('Webauthn', () => {
  afterEach(() => {
    sinon.restore()
  })

  describe('constructor()', () => {
    let validConfig

    beforeEach(() => {
      validConfig = {
        origin: 'http://localhost:3000',
        usernameField: 'name',
        userFields: ['name', 'displayName'],
        store: new MemoryAdapter(),
        rpName: 'ACME Corporation',
        credentialEndpoint: '/register',
        assertionEndpoint: '/login',
        challengeEndpoint: '/response',
        logoutEndpoint: '/logout',
        enableLogging: true,
        attestation: Dictionaries.AttestationConveyancePreference.NONE,
      }
    })

    it('rejects an invalid attestation', () => {
      assert.throws(() => new Webauthn({...validConfig, ...{attestation: 'invalid'}}),
                    'Invalid attestation value invalid. Must be one of "none", "direct", "indirect"')
    })

    it('maps user fields when using arrays', () => {
      let webauthn = new Webauthn({...validConfig, ...{userFields: ['one', 'two']}})
      assert.deepEqual({one: 'one', two: 'two'}, webauthn.config.userFields)
    })

    it('maps user fields when using objects', () => {
      let webauthn = new Webauthn({...validConfig, ...{userFields: {'one': 1, 'two' : 2}}})
      assert.deepEqual({one: 1, two: 2}, webauthn.config.userFields)
    })
  })

  describe('initialize()', () => {
    it('sets up the endpoints and returns the router', () => {
      let webauthn = new Webauthn({
        credentialEndpoint: 'credentialEndpoint',
        assertionEndpoint: 'assertionEndpoint',
        challengeEndpoint: 'challengeEndpoint',
        logoutEndpoint: 'logoutEndpoint',
      })

      let router = {
        post: (endpoint, handler) => {},
        get: (endpoint, handler) => {},
      }

      let routerMock = sinon.mock(router)
      routerMock.expects('post').withArgs('assertionEndpoint', sinon.match.func)
      routerMock.expects('post').withArgs('credentialEndpoint', sinon.match.func)
      routerMock.expects('post').withArgs('challengeEndpoint', sinon.match.func)
      routerMock.expects('post').withArgs('logoutEndpoint', sinon.match.func)
      routerMock.expects('get').withArgs('logoutEndpoint', sinon.match.func)

      sinon.stub(express, 'Router').returns(router)
      assert.equal(router, webauthn.initialize())
      routerMock.verify()
    })
  })
})
