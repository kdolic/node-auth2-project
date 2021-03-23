const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const User = require('../users/users-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { jwtSecret } = require("../secrets"); // use this secret!

/**
  [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

  response:
  status 201
  {
    "user"_id: 3,
    "username": "anna",
    "role_name": "angel"
  }
 */
router.post("/register", validateRoleName, (req, res, next) => {
  const {username, password, role_name} = req.body

  const hash = bcrypt.hashSync(password, 10)
  const userForDb = {username, password: hash, role_name}
  

  User.add(userForDb)
  .then(user => {
    res.status(201).json(user)
  })
  .catch(next)
});


/**
  [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "sue is back!",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
  }

  The token must expire in one day, and must provide the following information
  in its payload:

  {
    "subject"  : 1       // the user_id of the authenticated user
    "username" : "bob"   // the username of the authenticated user
    "role_name": "admin" // the role of the authenticated user
  }
 */
router.post("/login", checkUsernameExists, (req, res, next) => {
const {username, password} = req.body

User.findBy({username: username})
.then(([user]) => {
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = buildToken(user)
    res.status(200).json({ message: `${username} is back`, token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
})
.catch(error => {
  res.status(500).json({ message: error.message });
});
})

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  }

  const config = {
    expiresIn: '1d',
  }

  return jwt.sign(payload, jwtSecret, config)
}

module.exports = router;
