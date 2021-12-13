const router = require('express').Router();
const User = require('../users/users-model');
const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
  hashPassword,
  checkPassword,
} = require('./auth-middleware');

// [POST] /api/auth/register
router.post(
  '/register',
  checkUsernameFree,
  checkPasswordLength,
  hashPassword,
  (req, res, next) => {
    try {
      User.add(req.user).then((user) => {
        res.status(200).json(user);
      });
    } catch (err) {
      next(err);
    }
  }
);

// [POST] /api/auth/login
router.post(
  '/login',
  checkUsernameExists,
  checkPasswordLength,
  checkPassword,
  (req, res, next) => {
    try {
      res.status(200).json({ message: `Welcome ${req.body.username}!` });
    } catch (err) {
      next(err);
    }
  }
);

// [GET] /api/auth/logout
router.get('/logout', async (req, res, next) => {
  try {
    if (req.session.user) {
      req.session.destroy((err) =>
        err ? next(err) : res.json({ message: 'logged out' })
      );
    } else {
      res.json({ message: 'no session' });
    }
  } catch (err) {
    next(err);
  }
});

module.exports = router;
