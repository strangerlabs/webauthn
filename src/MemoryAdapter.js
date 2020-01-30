'use strict'

/**
 * Dependencies
 * @ignore
 */

/**
 * Module Dependencies
 * @ignore
 */

/**
 * Memory "Database" Adapater
 * @ignore
 */
class MemoryAdapter {
  constructor () {
    this.db = {}
  }

  async get (id) {
    const { [id]: item } = this.db

    if (!item) {
      return null
    }

    return item
  }

  async put (id, value) {
    this.db[id] = value
  }

  async delete (id) {
    if (this.db[id]) {
      delete this.db[id]
      return true
    }

    return false
  }
}

/**
 * Exports
 * @ignore
 */
module.exports = MemoryAdapter
