const User = require('../users/users-model');
const bcrypt = require('bcryptjs');

function restricted(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    next({
      status: 401,
      message: 'You shall not pass!',
    });
  }
}

async function checkUsernameFree(req, res, next) {
  const { username } = req.body;
  const [user] = await User.findBy({ username });
  if (user) {
    next({
      status: 422,
      message: 'Username taken',
    });
  } else {
    next();
  }
}

async function checkUsernameExists(req, res, next) {
  const { username } = req.body;
  const [user] = await User.findBy({ username });
  if (user) {
    next();
  } else {
    next({
      status: 401,
      message: 'Invalid credentials',
    });
  }
}

function checkPasswordLength(req, res, next) {
  const { password } = req.body;
  if (!password || password.length < 4) {
    next({
      status: 422,
      message: 'Password must be longer than 3 chars',
    });
  } else {
    next();
  }
}

function hashPassword(req, res, next) {
  const { password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  req.user = { ...req.body, password: hash };
  next();
}

async function checkPassword(req, res, next) {
  const { username, password } = req.body;
  const [user] = await User.findBy({ username });
  const isValid = bcrypt.compareSync(password, user.password);
  if (!isValid) {
    next({
      status: 401,
      message: 'Invalid credentials',
    });
  } else {
    req.session.user = user;
    next();
  }
}

module.exports = {
  restricted,
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength,
  hashPassword,
  checkPassword,
};
