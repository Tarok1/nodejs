const bcrypt = require('bcryptjs');
const User = require('../models/user');

exports.getLogin = (req, res, next) => {
  const errorMessage = req.flash('error');

  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: errorMessage.length ? errorMessage : null,
  });
};

exports.getSignup = (req, res, next) => {
  const errorMessage = req.flash('error');

  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: errorMessage.length ? errorMessage : null,
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  User.findOne({ email, })
    .then((user) => {
      if (!user) {
        req.flash('error', 'Invalid email.');

        return res.redirect('/login');
      }

      bcrypt.compare(password, user.password)
        .then((result) => {
          if (result) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/');
            });
          }

          req.flash('error', 'Invalid password.');
          res.redirect('login');
        })
        .catch(err => {
          res.redirect('/login');
          console.log(err)
        });
    })
    .catch(err => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const configrmPassword = req.body.confirmPassword;

  User.findOne({ email: email })
    .then((userDoc) => {
      if (userDoc) {
        req.flash('error', 'Email exists already, please pick a different one');
        return res.redirect('/signup');
      }

      return bcrypt.hash(password, 12)
        .then((hashPassword) => {
          const user = new User({
            email,
            password: hashPassword,
            cart: { items: [] },
          });
    
          return user.save();
        });
    })
    .then((result) => {
      res.redirect('/login');
    })
    .catch(err => console.log(err));
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};
