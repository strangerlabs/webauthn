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
 * Assertion Challenge Builder
 * @ignore
 */
class AssertionChallengeBuilder {
  constructor (service) {
    Object.defineProperty(this, 'service', { value: service })
    Object.defineProperty(this, 'result', { value: {} })
  }

  addAllowedCredential (options = {}) {
    const { PublicKeyCredentialType, AuthenticatorTransport } = Dictionaries
    let { allowCredentials = [] } = this.result

    if (!Array.isArray(allowCredentials)) {
      allowCredentials = [allowCredentials]
    }

    if (Array.isArray(options)) {
      options.forEach(option => this.addAllowedCredential(option))
      return this
    }

    const {
      id,
      type = PublicKeyCredentialType.PUBLIC_KEY,
      transports = Object.values(AuthenticatorTransport),
    } = options

    if (!id || !Object.values(PublicKeyCredentialType).includes(type)) {
      throw new Error('Invalid PublicKeyCredentialDescriptor. See https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialparameters')
    }

    // Add credential request
    allowCredentials.push({ type, id, transports })

    this.result.allowCredentials = allowCredentials
    return this
  }

  setUserVerification (userVerification = Dictionaries.UserVerificationRequirement.PREFERRED) {
    const values = Object.values(Dictionaries.UserVerificationRequirement)

    if (!values.includes(userVerification)) {
      throw new Error(`Invalid UserVerificationRequirement value. Must be one of "${values.join('", "')}".`)
    }

    this.result.userVerification = userVerification

    return this
  }

  setExtensions (extensions = {}) {
    this.extensions = extensions
    return this
  }

  build (override = {}) {
    const challenge = base64url(crypto.randomBytes(32))
    const { allowCredentials } = this.result

    if (!allowCredentials) {
      throw new Error('Requires at least one allowed credential.')
    }

    return { ...this.result, ...override, challenge }
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = AssertionChallengeBuilder
