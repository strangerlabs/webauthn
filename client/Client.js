
/**
 * Dependencies
 * @ignore
 */

/**
 * Module Dependencies
 * @ignore
 */
import base64url from './base64url'

/**
 * Client
 * @ignore
 */
class Client {
  constructor (options = {}) {
    const defaults = {
      pathPrefix: '/webauthn',
    }

    Object.assign(this, defaults, options)
  }

  static publicKeyCredentialToJSON (pubKeyCred) {
    if (pubKeyCred instanceof Array) {
      const arr = []

      for (let i of pubKeyCred) {
        arr.push(Client.publicKeyCredentialToJSON(i))
      }

      return arr
    }

    if (pubKeyCred instanceof ArrayBuffer) {
      return base64url.encode(pubKeyCred)
    }

    if (pubKeyCred instanceof Object) {
      const obj = {}

      for (let key in pubKeyCred) {
        obj[key] = Client.publicKeyCredentialToJSON(pubKeyCred[key])
      }

      return obj
    }

    return pubKeyCred
  }

  static generateRandomBuffer (len) {
    const buf = new Uint8Array(len || 32)
    window.crypto.getRandomValues(buf)
    return buf
  }

  static preformatMakeCredReq (makeCredReq) {
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge)
    makeCredReq.user.id = base64url.decode(makeCredReq.user.id)
    return makeCredReq
  }

  static preformatGetAssertReq (getAssert) {
    getAssert.challenge = base64url.decode(getAssert.challenge)

    for (let allowCred of getAssert.allowCredentials) {
      allowCred.id = base64url.decode(allowCred.id)
    }

    return getAssert
  }

  async getMakeCredentialsChallenge (formBody) {
    const response = await fetch(`${this.pathPrefix}/register`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formBody)
    })

    if (response.status === 403) {
      const failureMessage = (await response.json()).message
      const errorMessage = 'Registration failed'
      throw new Error(failureMessage ? `${errorMessage}: ${failureMessage}.` : `${errorMessage}.`)
    }

    if (response.status < 200 || response.status > 205) {
      throw new Error('Server responded with error.')
    }

    return await response.json()
  }

  async sendWebAuthnResponse (body) {
    const response = await fetch(`${this.pathPrefix}/response`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    })

    if (response.status !== 200) {
      throw new Error('Server responded with error.')
    }

    return await response.json()
  }

  async getGetAssertionChallenge (formBody) {
    const response = await fetch(`${this.pathPrefix}/login`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formBody)
    })

    if (response.status !== 200) {
      throw new Error('Server responded with error.')
    }

    return await response.json()
  }

  async register (data = {}) {
    try {
      const challenge = await this.getMakeCredentialsChallenge(data)
      const publicKey = Client.preformatMakeCredReq(challenge)
      const credential = await navigator.credentials.create({ publicKey })

      console.log('CREDENTIAL', credential)

      const credentialResponse = Client.publicKeyCredentialToJSON(credential)
      return await this.sendWebAuthnResponse(credentialResponse)

    } catch (err) {
      console.error(err)
    }
  }

  async login (data = {}) {
    try {
      const challenge = await this.getGetAssertionChallenge(data)
      const publicKey = Client.preformatGetAssertReq(challenge)
      const credential = await navigator.credentials.get({ publicKey })

      console.log('CREDENTIAL', credential)

      const credentialResponse = Client.publicKeyCredentialToJSON(credential)
      return await this.sendWebAuthnResponse(credentialResponse)

    } catch (err) {
      console.error(err)
    }
  }

  async logout () {
    const response = await fetch(`${this.pathPrefix}/logout`, {
      method: 'GET',
      credentials: 'include',
    })

    if (response.status !== 200) {
      throw new Error('Server responded with error.')
    }

    return await response.json()
  }
}

/**
 * Exports
 * @ignore
 */
export default Client
