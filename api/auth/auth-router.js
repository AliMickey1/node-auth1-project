// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')

const Users = require('../users/users-model')
const { checkPasswordLength, checkUsernameExists, checkUsernameFree } = require('./auth-middleware')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
  const { username, password } = req.body
  
  const hash =  bcrypt.hashSync(password, 8)
  const credentials = {
    username, 
    password: hash
  }

  Users.add(credentials)
    .then(save => {
      res.status(201).json(save)
    })
  // const post = {
  //   user_id,
  //   username
  // }
  // res.status(201).json(post)
    .catch(next)

})


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

  router.post('/login', checkUsernameExists, (req, res) => {

      // const { password } = Users.findBy(req.body.username)
      const { password } = req.body

      const valid = bcrypt.compareSync(req.user.password, password)
      if(valid) {
        req.session.user = req.user
        res.json({ message: `Welcome ${req.body.username}!` })
      } else {
        next({ status: 401, message: 'Invalid credentials' })
      }

  })

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

  router.get('/logout', (req, res) => {
    try{
      if(req.session.user) {
        req.session.destroy(err => {
          if(err) {
            res.send('error loggin out')
          } else {
            res.status(200).json({ message: 'logged out' })
          }
        }) 
      } else {
        res.status(200).json({ message: 'no session' })
      }
    }
    catch(err) {
      next(err)
    }
  })
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router