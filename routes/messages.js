const express = require('express')
const router = new express.Router()
const Message = require('../models/message')
const { ensureLoggedIn, ensureCorrectUser } = require('../middleware/auth')
const ExpressError = require('../expressError')

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get('/:id', ensureLoggedIn, async (req, res, next) => {
  try {
    const user = req.user.username
    const message = await Message.get(req.params.id)

    if (msg.to_user.username !== user && msg.from_user.username !== user) {
      throw new ExpressError("We're gonna pretend you didn't read that...", 401) 
    }

    res.json({message})
  } catch (e) {
    next(e)
  }
})

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post('/', ensureLoggedIn, async (req, res, next) => {
  try {
    const {to_username, body} = req.body
    const from_username = req.user.username
    const message = await Message.create({from_username, to_username, body})
    res.json({message})
  } catch (e) {
    next(e)
  }
})

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post('/:id/read', ensureLoggedIn, async (req, res, next) => {
  try {
    const user = req.user.username
    const msg = await Message.get(req.params.id)

    if (msg.to_user.username !== user) throw new ExpressError("We're gonna pretend you didn't read that...", 401)

    const message = await Message.markRead(req.params.id)
    res.json({message})
  } catch (e) {
    next(e)
  }
})

 module.exports = router