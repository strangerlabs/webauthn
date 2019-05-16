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
 * Level Adapter
 * @ignore
 */
class LevelAdapter {
  constructor (dbpath = 'userdb', options = {}) {
    this.db = new level(path.join(cwd, dbpath), Object.assign({}, LevelAdapter.levelOptions, options))
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

  async delete (id) {
    try {
      await this.db.get(id)
      await this.db.del(id)
      return true

    } catch (err) {
      if (err.notFound) {
        return false
      }

      throw err
    }
  }

  async search (startsWith = '', options = {}) {
    if (typeof startsWith === 'object') {
      options = startsWith
      startsWith = options.startsWith || options.gte || options.search
    }

    const { limit = -1, reverse = false, lte } = options

    return await new Promise((resolve, reject) => {
      const data = {}

      // Get all values that start with `startsWith`
      this.db.createReadStream({
        gte: startsWith,
        lte: lte ? lte : `${startsWith}\uffff`,
        limit,
        reverse,
      })
        .on('data', item => data[item.key] = item.value)
        .on('end', () => resolve(data))
        .on('error', err => reject(err))
    })
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = LevelAdapter
