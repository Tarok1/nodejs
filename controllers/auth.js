const User = require('../models/user');

exports.getLogin = (req, res, next) => {
    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        isAuthenticated: false,
    });
};

exports.postLogin = (req, res, next) => {
    User.findById('65dde01b488d324d82847460')
        .then((user) => {
            req.session.isLoggedIn = true;
            req.session.user = user;

            req.session.save((error) => {
                console.log(error);

                res.redirect('/');
            });
        })
        .catch((error) => {
            console.log(error)
        });
};

exports.postLogout = (req, res, next) => {
    req.session.destroy((error) => {
        console.log(error);

        res.redirect('/');
    });
}