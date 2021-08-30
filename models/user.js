/** User class for message.ly */
const db = require('../db')
const ExpressError = require('../expressError')
const bcrypt = require('bcrypt')
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require('../config')
const jwt = require('jsonwebtoken')

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    if (!username || !password || !first_name || !last_name || !phone) {
      throw new ExpressError('You must provide all info', 400)
    }

    const hashedPw = await bcrypt.hash(password, BCRYPT_WORK_FACTOR)
    const results = await db.query(`
      INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPw, first_name, last_name, phone])
    return results.rows[0]
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    if (!username || !password) throw new ExpressError('You must provide a username and a password', 400)
    const results = await db.query(`
      SELECT password
      FROM users
      WHERE username = $1`,
    [username])
    const user = results.rows[0]
    return user && await bcrypt.compare(password, user.password)
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const results = await db.query(`
      UPDATE users
        SET last_login_at = CURRENT_TIMESTAMP
        WHERE username = $1
        RETURNING username`,
      [username])

    if (!results.rows[0]) throw new ExpressError(`No user named ${username}`, 404)
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(`
      SELECT username, first_name, last_name, phone
        FROM users
    `)

    return results.rows
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(`
      SELECT username, first_name, last_name, phone, join_at, last_login_at
        FROM users
        WHERE username = $1
    `, [username])

    if (!results.rows[0]) throw new ExpressError(`No user named ${username}`, 404)

    return results.rows[0]
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(`
      SELECT m.id,
             m.to_username,
             u.first_name,
             u.last_name,
             u.phone,
             m.body,
             m.sent_at,
             m.read_at
      FROM messages AS m
        JOIN users AS u ON m.to_username = u.username
      WHERE from_username = $1
      `, [username])
    
    return results.rows.map(m => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = db.query(`
      SELECT m.id,
        m.from_username,
        u.first_name,
        u.last_name,
        u.phone,
        m.body,
        m.sent_at,
        m.read_at
      FROM messages AS m
        JOIN users AS u ON m.from_username = u.username
      WHERE to_username = $1
    `, [username])

    return (await results).rows.map(m => ({
      id: m.id,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }))
  }
}

module.exports = User;