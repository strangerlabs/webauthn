'use strict'

/**
 * Dependencies
 * @ignore
 */
const crypto = require('crypto')
const base64url = require('base64url')
const _ = require('lodash')

/**
 * Module Dependencies
 * @ignore
 */
const Dictionaries = require('./Dictionaries')

/**
 * Attestation Challenge Builder
 * @ignore
 */
class AttestationChallengeBuilder {
  constructor (service) {
    Object.defineProperty(this, 'service', { value: service })
    Object.defineProperty(this, 'result', { value: {} })
  }

  setRelyingPartyInfo (options = {}) {
    this.result.rp = _.pick(options, [
      'id',
      'name',
      'icon',
    ])

    return this
  }

  setUserInfo (options = {}) {
    const { usernameField } = this.service.config
    const { id, [usernameField]: name } = options

    if (!id) {
      throw new Error('id required')
    }

    if (!name) {
      throw new Error(`${usernameField} required`)
    }

    this.result.user = _.pick(options, [
      'id',
      'displayName',
      'icon',
    ])

    this.result.user.name = name

    if (!this.result.user.displayName) {
      this.result.user.displayName = name
    }

    return this
  }

  addCredentialRequest (options = {}) {
    const { PublicKeyCredentialType } = Dictionaries
    let { pubKeyCredParams = [] } = this.result

    if (!Array.isArray(pubKeyCredParams)) {
      pubKeyCredParams = [pubKeyCredParams]
    }

    if (Array.isArray(options)) {
      options.forEach(option => this.addCredentialRequest(option))
      return this
    }

    const { type, alg } = options

    if (!type || !alg || !Object.values(PublicKeyCredentialType).includes(type)) {
      throw new Error('Invalid PublicKeyCredentialParameters. See https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialparameters')
    }

    // Add credential request
    pubKeyCredParams.push({ type, alg })

    this.result.pubKeyCredParams = pubKeyCredParams
    return this
  }

  addCredentialExclusion (options = {}) {
    const { AuthenticatorTransport, PublicKeyCredentialType } = Dictionaries
    let { excludeCredentials = [] } = this.result

    if (!Array.isArray(excludeCredentials)) {
      excludeCredentials = [excludeCredentials]
    }

    if (Array.isArray(options)) {
      options.forEach(option => this.addCredentialRequest(option))
      return this
    }

    const { type, id, transports = [] } = options

    if (
      !type
      || !id
      || !Object.values(PublicKeyCredentialType).includes(type)
      || !Array.isArray(transports)
    ) {
      throw new Error('Invalid PublicKeyCredentialDescriptor. See https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor')
    }

    const transportValues = Object.values(AuthenticatorTransport)
    transports.forEach(transport => {
      if (!transportValues.includes(transport)) {
        throw new Error('Invalid AuthenticatorTransport. See https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport')
      }
    })

    // Add credential request
    excludeCredentials.push({ type, id, transports })

    this.result.excludeCredentials = excludeCredentials
    return this
  }

  setUserVerification (userVerification = Dictionaries.UserVerificationRequirement.PREFERRED) {
    const { authenticatorSelection = {} } = this.result
    const values = Object.values(Dictionaries.UserVerificationRequirement)

    if (!values.includes(userVerification)) {
      throw new Error(`Invalid UserVerificationRequirement value. Must be one of "${values.join('", "')}".`)
    }

    this.result.authenticatorSelection = {
      ...authenticatorSelection,
      userVerification,
    }

    return this
  }

  setResidentKeyRequired (requireResidentKey = true) {
    const { authenticatorSelection = {} } = this.result

    this.result.authenticatorSelection = {
      ...authenticatorSelection,
      requireResidentKey,
    }

    return this
  }

  setAuthenticator (authenticatorAttachment = Dictionaries.AuthenticatorAttachment.PLATFORM) {
    const { authenticatorSelection = {} } = this.result
    const values = Object.values(Dictionaries.AuthenticatorAttachment)

    if (!values.includes(authenticatorAttachment)) {
      throw new Error(`Invalid AuthenticatorAttachment value. Must be one of "${values.join('", "')}".`)
    }

    this.result.authenticatorSelection = {
      ...authenticatorSelection,
      authenticatorAttachment,
    }

    return this
  }

  setAttestationType (attestation = Dictionaries.AttestationConveyancePreference.DIRECT) {
    const values = Object.values(Dictionaries.AttestationConveyancePreference)

    if (!values.includes(attestation)) {
      throw new Error(`Invalid AttestationConveyancePreference value. Must be one of "${values.join('", "')}".`)
    }

    this.result.attestation = attestation

    return this
  }

  setExtensions (extensions = {}) {
    this.extensions = extensions
    return this
  }

  build (override = {}) {
    const challenge = base64url(crypto.randomBytes(32))
    const { rp, user, attestation, pubKeyCredParams } = this.result

    if (!rp) {
      throw new Error('Requires RP information')
    }

    if (!user) {
      throw new Error('Requires user information')
    }

    if (!attestation) {
      this.setAttestationType()
    }

    if (!pubKeyCredParams || !pubKeyCredParams.length) {
      // ECDSA P-256 with SHA2-256 hash
      this.addCredentialRequest({ type: 'public-key', alg: -7 })
    }

    return { ...this.result, ...override, challenge }
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = AttestationChallengeBuilder
