let assert = require('assert')
let sinon = require('sinon')

let AttestationChallengeBuilder = require('../src/AttestationChallengeBuilder')

describe('AttestationChallengeBuilder', () => {
  describe('addCredentialExclusion', () => {
    let service = {
      config: {
        usernameField: 'id',
      },
    }

    it('adds a single credential to the exclusion list', () => {
      let credential = { id: 'id', type: 'public-key', transports: ['usb'] }
      let attestation = new AttestationChallengeBuilder(service)
          .setUserInfo({id: 'nina'})
          .setRelyingPartyInfo({id: 'rp.com'})
          .addCredentialExclusion(credential)
          .build()
      assert.deepEqual([credential], attestation.excludeCredentials)
    })

    it('adds an array of credentials to the exclusion list', () => {
      let credential1 = { id: 'id1', type: 'public-key', transports: ['usb'] }
      let credential2 = { id: 'id2', type: 'public-key', transports: ['nfc'] }
      let attestation = new AttestationChallengeBuilder(service)
          .setUserInfo({id: 'nina'})
          .setRelyingPartyInfo({id: 'rp.com'})
          .addCredentialExclusion([credential1, credential2])
          .build()
      assert.deepEqual([credential1, credential2], attestation.excludeCredentials)
    })

    it('includes an empty excludeCredentials if not called', () => {
      let attestation = new AttestationChallengeBuilder(service)
          .setUserInfo({id: 'nina'})
          .setRelyingPartyInfo({id: 'rp.com'})
          .build()
      assert.deepEqual([], attestation.excludeCredentials)
    })

    it('throws if the credential is not valid', () => {
      let credential = { id: null, type: 'public-key', transports: ['usb'] }
      assert.throws(() => {
        new AttestationChallengeBuilder(service)
          .setUserInfo({id: 'nina'})
          .setRelyingPartyInfo({id: 'rp.com'})
          .addCredentialExclusion(credential)
      }, new Error('Invalid PublicKeyCredentialDescriptor. See https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor'))
    })
  })
})
