'use strict'

/**
 * Dictionaries
 * @ignore
 */
const Dictionaries = {
  /**
   * UserVerificationRequirement
   * @link https://www.w3.org/TR/webauthn/#enumdef-userverificationrequirement
   */
  UserVerificationRequirement: {
    REQUIRED: 'required',
    PREFERRED: 'preferred',
    DISCOURAGED: 'discouraged',
  },

  /**
   * AuthenticatorAttachment
   * @link https://www.w3.org/TR/webauthn/#enumdef-authenticatorattachment
   */
  AuthenticatorAttachment: {
    PLATFORM: 'platform',
    CROSS_PLATFORM: 'cross-platform',
  },

  /**
   * AttestationConveyancePreference
   * @link https://www.w3.org/TR/webauthn/#attestation-convey
   */
  AttestationConveyancePreference: {
    NONE: 'none',
    DIRECT: 'direct',
    INDIRECT: 'indirect',
  },

  /**
   * PublicKeyCredentialType
   * @link https://www.w3.org/TR/webauthn/#credentialType
   */
  PublicKeyCredentialType: {
    PUBLIC_KEY: 'public-key',
  },

  /**
   * AuthenticatorTransport
   * @link https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport
   */
  AuthenticatorTransport: {
    USB: 'usb',
    NFC: 'nfc',
    BLE: 'ble',
    INTERNAL: 'internal',
  },
}

/**
 * Exports
 * @ignore
 */
Object.freeze(Dictionaries)
module.exports = Dictionaries
