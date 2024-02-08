const express = require('express');
const session = require('express-session');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');
const dotenv = require('dotenv');

dotenv.config();

const app = express();


const PORT = process.env.PORT || 3000;
const EXPRESS_SESSION_SECRET = process.env.EXPRESS_SESSION_SECRET;

const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;
const OAUTH_AUTHORIZATION_URL = process.env.OAUTH_AUTHORIZATION_URL;
const OAUTH_TOKEN_URL = process.env.OAUTH_TOKEN_URL;
const OAUTH_USER_INFO = process.env.OAUTH_USER_INFO;
const OAUTH_REDIRECT_URL = process.env.OAUTH_REDIRECT_URL;
const OAUTH_CALLBACK_URL = OAUTH_REDIRECT_URL + "/auth/callback"



app.use(session({
  secret: EXPRESS_SESSION_SECRET,
  resave: true,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// Configure OAuth2 strategy
passport.use('oauth2', new OAuth2Strategy({
  authorizationURL: OAUTH_AUTHORIZATION_URL,
  tokenURL: OAUTH_TOKEN_URL,
  clientID: OAUTH_CLIENT_ID,
  clientSecret: OAUTH_CLIENT_SECRET,
  callbackURL: OAUTH_CALLBACK_URL,
}, async (accessToken, refreshToken, profile, done) => {
  try {

    return done(null, { accessToken, refreshToken, profile });
  } catch (error) {
    return done(error);
  }
}));


// Authenticate endpoint
app.get('/auth', passport.authenticate('oauth2'));


// Callback endpoint
app.get('/auth/callback', passport.authenticate('oauth2', {
  successRedirect: '/profile',
  failureRedirect: '/login',
}));

// Profile endpoint
app.get('/profile', ensureAuthenticated, async (req, res) => {
  try {
    const userInfoResponse = await fetch(OAUTH_USER_INFO, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${req.user.accessToken}`
      }
    });
    const userInfo = await userInfoResponse.json();
    res.json(userInfo);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user information' });
  }
});


function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else
  res.redirect('/login');
}

app.get('/login', (req, res) => {
  res.send('<a href="/auth">Login</a');
});

app.get('/', (req, res) => {
  res.redirect('/login');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`);
});
