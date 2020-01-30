'use strict'

/**
 * Dependencies
 * @ignore
 */
const crypto = require('crypto')
const express = require('express')
const base64url = require('base64url')
const cbor = require('cbor')
const iso_3166_1 = require('iso-3166-1')
const { Certificate } = require('@fidm/x509')

/**
 * Module Dependencies
 * @ignore
 */
const MemoryAdapter = require('./MemoryAdapter')
const AttestationChallengeBuilder = require('./AttestationChallengeBuilder')
const AssertionChallengeBuilder = require('./AssertionChallengeBuilder')
const Dictionaries = require('./Dictionaries')

/**
 * Webauthn RP
 * @ignore
 */
class Webauthn {
  constructor (options = {}) {
    this.config = Object.assign({
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
      authenticator: Dictionaries.AuthenticatorAttachment.CROSS_PLATFORM,
    }, options)

    const attestationOptions = Object.values(Dictionaries.AttestationConveyancePreference)
    if (!attestationOptions.includes(this.config.attestation)) {
      throw new Error(`Invalid attestation value ${attestation}. Must be one of "${attestationOptions.join('", "')}".`)
    }

    // Map object for field names from req param to db name.
    if (Array.isArray(this.config.userFields)) {
      // Ensure mapping
      this.config.userFields = this.config.userFields
        .reduce((state, current) => {
          state[current] = current
          return state
        }, {})
    }
  }

  get store () {
    return this.config.store
  }

  initialize () {
    const {
      credentialEndpoint,
      assertionEndpoint,
      challengeEndpoint,
      logoutEndpoint,
    } = this.config

    const router = express.Router()

    router.post(assertionEndpoint, this.login())
    router.post(credentialEndpoint, this.register())
    router.post(challengeEndpoint, this.response())
    router.post(logoutEndpoint, this.logout())
    router.get(logoutEndpoint, this.logout())

    return router
  }

  register (options = {}) {
    const usernameField = this.config.usernameField || options.usernameField

    return async (req, res, next) => {
      if (!req.body) {
        return res.status(400).json({ message: 'bad request' })
      }

      if (this.config.enableLogging) console.log('REGISTER', req.body)

      const username = req.body[usernameField]
      if (!username) {
        return res.status(400).json({ message: 'bad request' })
      }

      let user = await this.store.get(username)
      if (!user) {
        user = {
          id: base64url(crypto.randomBytes(32)),
          [usernameField]: username,
          credentials: [],
        }
        Object.entries(this.config.userFields).forEach(([bodyKey, dbKey]) => {
          user[dbKey] = req.body[bodyKey]
        })
        if (this.config.enableLogging) console.log('PUT', user)
        await this.store.put(username, user)
        if (this.config.enableLogging) console.log('STORED')
      }

      const attestation = new AttestationChallengeBuilder(this)
        .setUserInfo(user)
        .setAttestationType(this.config.attestation)
        .setAuthenticator(this.config.authenticator)
        .addCredentialExclusion(
            user.credentials.map(credential => ({ id: credential.credID })))
        .setRelyingPartyInfo({ name: this.config.rpName || options.rpName })
        .build({ status: 'ok' })

      req.session.challenge = attestation.challenge
      req.session[usernameField] = username

      if (this.config.enableLogging) console.log('DONE', attestation)

      return res.status(200).json(attestation)
    }
  }

  login (options = {}) {
    const usernameField = this.config.usernameField || options.usernameField

    return async (req, res, next) => {
      if (!req.body) {
        return res.status(400).json({
          message: 'bad request',
        })
      }

      const { [usernameField]: username } = req.body

      if (!username) {
        return res.status(400).json({
          message: `${usernameField} required`,
        })
      }

      try {
        const user = await this.store.get(username)

        if (!user) {
          return res.status(401).json({
            message: 'user does not exist',
          })
        }

        if (user.credentials.length === 0) {
          return res.status(401).json({
            message: 'user has not registered an authenticator',
          })
        }

        const assertion = new AssertionChallengeBuilder(this)
            .addAllowedCredential(
                user.credentials.map(credential => ({ id: credential.credID })))
            .build({ status: 'ok' })

        req.session.challenge = assertion.challenge
        req.session[usernameField] = username

        if (this.config.enableLogging) console.log('LOGIN', assertion)

        return res.status(200).json(assertion)

      } catch (err) {
        return next(err)
      }
    }
  }

  logout (options = {}) {
    return async (req, res) => {
      req.session.destroy(err => {
        if (err) {
          throw err
        }

        return res.status(200).json({
          message: 'logged out',
          status: 'ok',
        })
      })
    }
  }

  response (options = {}) {
    const usernameField = this.config.usernameField || options.usernameField

    return async (req, res, next) => {
      if (!req.body) {
        return res.status(400).json({ message: 'bad bequest' })
      }

      if (this.config.enableLogging) console.log('RESPONSE', req.body)

      const {
        id,
        rawId,
        response,
        type,
      } = req.body

      if (!id || !rawId || !response || !type) {
        return res.status(400).json({ message: 'response missing one or more of id/rawId/response/type fields' })
      }

      if (type !== 'public-key') {
        return res.status(400).json({ message: 'response type must be \'public-key\'' })
      }

      let clientData
      try {
        const json = base64url.decode(response.clientDataJSON)
        clientData = JSON.parse(json)
      } catch (err) {
        return res.status(400).json({ message: 'failed to decode client data' })
      }

      const { challenge, origin } = clientData

      if (!challenge || challenge !== req.session.challenge) {
        return res.status(400).json({ message: 'mismatched challenge' })
      }

      if (!origin || origin !== this.config.origin) {
        return res.status(400).json({ message: 'mismatched origin' })
      }

      const username = req.session[usernameField]
      if (!username) {
        return res.status(400).json({ message: `mismatched ${usernameField}` })
      }

      let result
      const user = await this.store.get(username)

      if (this.config.enableLogging) console.log('USER', user)

      try {
        if (response.attestationObject !== undefined) {
          result = this.verifyAuthenticatorAttestationResponse(response);

          if (result.verified) {
            user.credentials.push(result.authrInfo)
            await this.store.put(username, user)
          }

        } else if (response.authenticatorData !== undefined) {
          let authenticator =
              user.credentials.find(credential => credential.credID === id)

          result = Webauthn.verifyAuthenticatorAssertionResponse(
              response, authenticator, this.config.enableLogging)

          if (result.verified) {
            if (result.counter <= authenticator.counter)
              throw new Error('Authr counter did not increase!')

            authenticator.counter = result.counter
            await this.store.put(username, user)
          }

        } else {
          return res.status(401).json({ status: 'failed', message: 'failed to determine response type' })
        }

      } catch (err) {
        console.error(err)
        return res.status(401).json({ status: 'failed', message: 'failed to authenticate' })
      }

      if (result.verified) {
        req.session.loggedIn = true
        return res.status(200).json({ status: 'ok' })

      } else {
        return res.status(401).json({ status: 'failed', message: 'verification failed' })
      }
    }
  }

  getStrategy () {
    // TODO
  }

  authenticate (options = {}) {
    const {
      failureRedirect,
      usernameField = this.config.usernameField,
    } = options

    return async (req, res, next) => {
      if (!req.session) {
        next(new Error('No session found. Did you set up express-session correctly?'))
      }

      const fail = () => {
        if (failureRedirect) {
          return res.redirect(failureRedirect)
        } else {
          return res.status(401).json({
            status: 'failed',
            message: 'Unauthorized',
          })
        }
      }

      if (!req.session.loggedIn) {
        return fail()
      }

      try {
        // Check session for logged in user
        const username = req.session[usernameField]
        if (!username) {
          return fail()
        }

        // Lookup user
        const user = await this.store.get(username)

        // User doesn't exist
        if (!user) {
          return fail()
        }

        // Assign to request
        req.user = user
        return next()

      } catch (err) {
        return next(err)
      }
    }
  }

  /**
   * Helpers
   * @ignore
   */

  verifyAuthenticatorAttestationResponse (webauthnResponse) {
    const attestationBuffer = base64url.toBuffer(webauthnResponse.attestationObject);
    const ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];

    if (this.config.enableLogging) console.log('CTAP_RESPONSE', ctapMakeCredResp)

    const authrDataStruct = Webauthn.parseMakeCredAuthData(ctapMakeCredResp.authData);
    if (this.config.enableLogging) console.log('AUTHR_DATA_STRUCT', authrDataStruct)

    if (!(authrDataStruct.flags & 0x01)) // U2F_USER_PRESENTED
      throw new Error('User was NOT presented durring authentication!');

    const publicKey = Webauthn.COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)

    const response = { 'verified': false };
    if (ctapMakeCredResp.fmt === 'none') {
      if (this.config.enableLogging) console.log('None attestation')
      response.verified = this.config.attestation == Dictionaries.AttestationConveyancePreference.NONE
    } else if (ctapMakeCredResp.fmt === 'fido-u2f') {
      const clientDataHash = Webauthn.hash(base64url.toBuffer(webauthnResponse.clientDataJSON))
      const reservedByte = Buffer.from([0x00]);
      const signatureBase = Buffer.concat([reservedByte, authrDataStruct.rpIdHash, clientDataHash, authrDataStruct.credID, publicKey]);

      const PEMCertificate = Webauthn.ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
      const signature = ctapMakeCredResp.attStmt.sig;

      response.verified = Webauthn.verifySignature(signature, signatureBase, PEMCertificate)
    } else if (ctapMakeCredResp.fmt === 'packed' && ctapMakeCredResp.attStmt.hasOwnProperty('x5c')) {
      if (this.config.enableLogging) console.log('Packed attestation')
      const clientDataHash = Webauthn.hash(base64url.toBuffer(webauthnResponse.clientDataJSON))
      const signatureBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);

      const PEMCertificate = Webauthn.ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
      const signature = ctapMakeCredResp.attStmt.sig;

      const pem = Certificate.fromPEM(PEMCertificate);

      // Getting requirements from https://www.w3.org/TR/webauthn/#packed-attestation
      const aaguid_ext = pem.getExtension('1.3.6.1.4.1.45724.1.1.4')

      response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
        // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
        Webauthn.verifySignature(signature, signatureBase, PEMCertificate) &&
        // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
        pem.version == 3 &&
        // ISO 3166 valid country
        typeof iso_3166_1.whereAlpha2(pem.subject.countryName) !== 'undefined' &&
        // Legal name of the Authenticator vendor (UTF8String)
        pem.subject.organizationName &&
        // Literal string “Authenticator Attestation” (UTF8String)
        pem.subject.organizationalUnitName === 'Authenticator Attestation' &&
        // A UTF8String of the vendor’s choosing
        pem.subject.commonName &&
        // The Basic Constraints extension MUST have the CA component set to false
        !pem.extensions.isCA &&
        // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
        // verify that the value of this extension matches the aaguid in authenticatorData.
        // The extension MUST NOT be marked as critical.
        (aaguid_ext != null ?
          (authrDataStruct.hasOwnProperty('aaguid') ?
            !aaguid_ext.critical && aaguid_ext.value.slice(2).equals(authrDataStruct.aaguid) : false)
          : true);

      // Self signed
    } else if (ctapMakeCredResp.fmt === 'packed') {
      if (this.config.enableLogging) console.log('Self signed attestation')
      const clientDataHash = Webauthn.hash(base64url.toBuffer(webauthnResponse.clientDataJSON))
      const signatureBase = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);
      const PEMCertificate = Webauthn.ASN1toPEM(publicKey);

      const { attStmt: { sig: signature, alg } } = ctapMakeCredResp

      response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
        // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
        Webauthn.verifySignature(signature, signatureBase, PEMCertificate) && alg === -7
    } else if (ctapMakeCredResp.fmt === 'android-safetynet') {
      if (this.config.enableLogging) {
        console.log("Android safetynet request\n")
        console.log(ctapMakeCredResp)
      }

      let [header, payload, signature] = ctapMakeCredResp.attStmt.response.toString('utf8').split('.')
      const signatureBase = Buffer.from([header, payload].join('.'))

      header = JSON.parse(base64url.decode(header))
      payload = JSON.parse(base64url.decode(payload))
      signature = base64url.toBuffer(signature)

      if (this.config.enableLogging) {
        console.log('JWS HEADER', header)
        console.log('JWS PAYLOAD', payload)
        console.log('JWS SIGNATURE', signature)
      }

      const PEMCertificate = Webauthn.ASN1toPEM(Buffer.from(header.x5c[0], 'base64'))

      const pem = Certificate.fromPEM(PEMCertificate)

      if (this.config.enableLogging) console.log('PEM', pem)

      response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
        // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
        Webauthn.verifySignature(signature, signatureBase, PEMCertificate) &&
        // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
        pem.version == 3 &&
        pem.subject.commonName === 'attest.android.com'
    } else {
      throw new Error(`Unsupported attestation format: ${ctapMakeCredResp.fmt}`);
    }

    if (response.verified) {
      response.authrInfo = {
        fmt: 'fido-u2f',
        publicKey: base64url.encode(publicKey),
        counter: authrDataStruct.counter,
        credID: base64url.encode(authrDataStruct.credID),
        transports: webauthnResponse.transports,
      }
      if (this.config.enableLogging) console.log('RESPONSE', response)
    } else if (this.config.enableLogging) {
      console.log('MakeCredential request could not be verified')
    }

    return response
  }

  static verifyAuthenticatorAssertionResponse (webauthnResponse, authr, enableLogging = false) {
    const authenticatorData = base64url.toBuffer(webauthnResponse.authenticatorData)

    const response = { 'verified': false }
    if (['fido-u2f'].includes(authr.fmt)) {
      const authrDataStruct = Webauthn.parseGetAssertAuthData(authenticatorData)
      if (enableLogging) console.log('AUTH_DATA', authrDataStruct)

      if (!(authrDataStruct.flags & 0x01)) {// U2F_USER_PRESENTED
        throw new Error('User was not presented durring authentication!')
      }

      const clientDataHash = Webauthn.hash(base64url.toBuffer(webauthnResponse.clientDataJSON))
      const signatureBase = Buffer.concat([authenticatorData, clientDataHash]);

      const publicKey = Webauthn.ASN1toPEM(base64url.toBuffer(authr.publicKey))
      const signature = base64url.toBuffer(webauthnResponse.signature)

      response.counter = authrDataStruct.counter
      response.verified = Webauthn.verifySignature(signature, signatureBase, publicKey)

    }

    return response
  }

  static hash (data) {
    return crypto.createHash('sha256')
      .update(data)
      .digest()
  }

  static verifySignature (signature, data, publicKey) {
    return crypto.createVerify('SHA256')
      .update(data)
      .verify(publicKey, signature)
  }

  static parseGetAssertAuthData (buffer) {
    const rpIdHash = buffer.slice(0, 32)
    buffer = buffer.slice(32)

    const flagsBuf = buffer.slice(0, 1)
    buffer = buffer.slice(1)

    const flags = flagsBuf[0]

    const counterBuf = buffer.slice(0, 4)
    buffer = buffer.slice(4)

    const counter = counterBuf.readUInt32BE(0)

    return { rpIdHash, flagsBuf, flags, counter, counterBuf }
  }

  static parseMakeCredAuthData (buffer) {
    const rpIdHash = buffer.slice(0, 32)
    buffer = buffer.slice(32)

    const flagsBuf = buffer.slice(0, 1)
    buffer = buffer.slice(1)

    const flags = flagsBuf[0]

    const counterBuf = buffer.slice(0, 4)
    buffer = buffer.slice(4)

    const counter = counterBuf.readUInt32BE(0)

    const aaguid = buffer.slice(0, 16)
    buffer = buffer.slice(16)

    const credIDLenBuf = buffer.slice(0, 2)
    buffer = buffer.slice(2)

    const credIDLen = credIDLenBuf.readUInt16BE(0)

    const credID = buffer.slice(0, credIDLen)
    buffer = buffer.slice(credIDLen)

    const COSEPublicKey = buffer

    return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
  }

  static COSEECDHAtoPKCS (COSEPublicKey) {
    const coseStruct = cbor.decodeAllSync(COSEPublicKey)[0]
    const tag = Buffer.from([0x04])
    const x = coseStruct.get(-2)
    const y = coseStruct.get(-3)

    return Buffer.concat([tag, x, y])
  }

  static ASN1toPEM (pkBuffer) {
    if (!Buffer.isBuffer(pkBuffer)) {
      throw new Error("ASN1toPEM: pkBuffer must be Buffer.")
    }

    let type
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
      pkBuffer = Buffer.concat([
        new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
        pkBuffer
      ])

      type = 'PUBLIC KEY'
    } else {
      type = 'CERTIFICATE'
    }

    const b64cert = pkBuffer.toString('base64')

    let PEMKey = ''
    for (let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
      const start = 64 * i
      PEMKey += b64cert.substr(start, 64) + '\n'
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`
    return PEMKey
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = Webauthn
