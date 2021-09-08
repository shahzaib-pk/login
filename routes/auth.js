const Joi = require('joi');
const { User } = require('../models/user');
const validate = require('../middleware/validate');
const bcrypt = require('bcrypt');
const express = require('express');
const auth = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const router = express.Router();

router.post('/', validate(validateAuth), async (req, res) => {    
    let user = await User.findOne({ email: req.body.email });
    if(!user) return res.status(400).send('Invalid email or password.');

    const validPassword = await bcrypt.compare(req.body.password, user.password);
    if (!validPassword) return res.status(400).send('Invalid email or password.');

    const token = User.generateAuthToken(user._id);
    const refreshToken = User.generateRefreshToken(user._id);

    res.send({jwtToken: token, refreshToken: refreshToken});
});

router.post('/refresh-token', async (req, res) => {   

  try {
    const refreshToken = req.header('x-refresh-token');
    if(!refreshToken) return res.status(401).send('No token provided.');

    const payload = jwt.verify(refreshToken, config.get('jwtRefreshKey'));
    const token = User.generateAuthToken(payload._id);
    res.send({jwtToken: token});
  } 
  catch (error) {
    res.status(400).send('Invalid token.')
  }

});

function validateAuth(req) {
    const schema = {
      email: Joi.string().min(5).max(255).required().email(),
      password: Joi.string().min(5).max(255).required()
    };
  
    return Joi.validate(req, schema);
}

module.exports = router;