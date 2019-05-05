'use strict'

/**
 * Dependencies
 * @ignore
 */
const cwd = process.cwd()
const fs = require('fs')
const path = require('path')
const level = require('level')

/**
 * Module Dependencies
 * @ignore
 */

/**
 * Basic Model
 * @ignore
 */
class BasicModel {
  constructor (dbpath = 'userdb', options = {}) {
    this.db = new level(path.join(cwd, dbpath), Object.assign({}, BasicModel.levelOptions, options))
  }

  static get levelOptions () {
    return {
      valueEncoding: 'json',
    }
  }

  async get (id) {
    try {
      return await this.db.get(id)

    } catch (err) {
      if (err.notFound) {
        return null
      }

      throw err
    }
  }

  async put (id, value) {
    return await this.db.put(id, value)
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = BasicModel
