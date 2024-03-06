const express = require('express');
const { check, body } = require('express-validator');

const User = require('../models/user');
const authController = require('../controllers/auth');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post(
    '/login',
    [
        body('email', 'Please enter a valid email.').isEmail().normalizeEmail(),
        body('password', 'Password has to be valid').isLength({ min: 3 }).isAlphanumeric().trim(),
    ],
    authController.postLogin,
);

router.post(
    '/signup',
    [
        check('email').isEmail().withMessage('Please enter a valid email.').custom((value, { req }) => {
            return User.findOne({ email: req.body.email }).then((userDoc) => {
                if (userDoc) {
                    return Promise.reject('Email exists already');
                }
            });
        }).normalizeEmail(),
        body('password', 'Password has to be more than 3 character').isLength({ min: 3 }).isAlphanumeric().withMessage().trim(),
        body('confirmPassword', 'Password and confirm password fields have to match.').custom((value, { req }) => {
            if (value !== req.body.password) {
                return false;
            }

            return true;
        }).trim(),
    ],
    authController.postSignup,
);

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('/new-password', authController.postNewPassword);

module.exports = router;