const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');

// Load Secrets
const keys = require('../../config/keys');

// Load User model
const User = require('../../models/User');

// @route GET api/users/test
// @Description Test users route
// @access Public
router.get('/test', (req, res) => res.json({msg: 'User Works!'}));

// @route GET api/users/register
// @Description Register User
// @access Public
router.post('/register', (req, res) => {
    User.findOne({ email: req.body.email })
    .then(user => {
        if(user)    {
            return res.status(400).json({email: 'Email Already Exist'});
        } else  {
            const avatar = gravatar.url(req.body.email, {
                s: '200', //Size
                r: 'pg', //Rating
                d: 'mm' //Default
            });

            const newUser = new User({
                name: req.body.name,
                email: req.body.email,
                avatar,
                password: req.body.password
            });

            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                    if(err) throw err;
                    newUser.password = hash;
                    newUser.save()
                    .then(user => res.json(user))
                    .catch(err => console.log(err));
                } )
            })
        }
    })
});


// @route GET api/users/login
// @Description User Login / Return JWT Token
// @access Public
router.post('/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    // Find by User
    User.findOne({email})
        .then(user => {

            // Check for User
            if(!user)   {
                return res.status(404).json({email: 'User not foud!'});
            }

            // Check for Password
            if(password != null)    {
                bcrypt.compare(password, user.password)
                .then(isMatch =>    {
                    if(isMatch) {
                        // User Matched
                        const payload = { id: user.id, name: user.name, avatar: user.avatar };  // Creating JWT Payload

                        // Sign Token
                        jwt.sign(
                            payload,
                            keys.secretOrKey,
                            { expiresIn: 3600 },
                            (error, token) => {
                                res.json({
                                    success: true,
                                    token: 'Bearer ' + token
                                });
                        })
                    } else  {
                        return res.status(400).json({msg: 'Passsword Incorrect!'});
                    }
                });    
            } else {
                return res.status(400).json({msg: 'Please enter the password!'});
            }
            
        }); 
});


// @route GET api/users/currect
// @Description  Return Current User
// @access Private
router.get('/currect', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email
    });
});

module.exports = router;