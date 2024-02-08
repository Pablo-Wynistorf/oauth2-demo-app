const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');

dotenv.config();


const app = express();
app.use(bodyParser.json());
app.use(cookieParser()); 
app.use(bodyParser.urlencoded({ extended: true }));


const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;

const DATABASE_URI = process.env.DATABASE_URI;



function connectToDatabase() {
  mongoose.connect(DATABASE_URI);
}
const db = mongoose.connection;

connectToDatabase();

db.on('error', () => {
  console.log('MongoDB connection error. Reconnecting...');
  setTimeout(connectToDatabase, 5000);
});

db.on('disconnected', () => {
  console.log('MongoDB disconnected. Reconnecting...');
  setTimeout(connectToDatabase, 5000);
  return;
});

db.on('connected', () => {
  console.log('Connected to MongoDB');
});


// Define schemas
const ClientSchema = new mongoose.Schema({
  client_id: String,
  client_secret: String,
  redirect_uri: String,
});

const UserSchema = new mongoose.Schema({
  userId: String,
  username: String,
  email: String,
  password: String,
  oauth_authorizationCode: String,
});

// Define models
const oauthClientDB = mongoose.model('oauthClientDB', ClientSchema);
const userDB = mongoose.model('userDB', UserSchema);


// Oauth2 authorize endpoint
app.get('/api/oauth/authorize', async (req, res) => {
  const { client_id } = req.query;
  const access_token = req.cookies.access_token;
  try {
    const oauth_client = await oauthClientDB.findOne({ client_id });

    const oauth_client_url = oauth_client.redirect_uri;
    if (!oauth_client) {
      return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client' });
    }
    jwt.verify(access_token, JWT_SECRET, async (error, decoded) => {
      if (error) {
        return res.redirect(`/login?redirect_uri=${oauth_client_url}`);
      }
      const { userId, sid } = decoded;
      const user = await userDB.findOne({ userId, sid });
      if (!user) {
        return res.redirect(`/login?redirect_uri=${oauth_client_url}`);
      }
      const redirect_uri = oauth_client.redirect_uri;
      const authorizationCode = [...Array(35)].map(() => Math.random().toString(36)[2]).join('');
      
      await userDB.updateOne({ userId }, { $set: { oauth_authorizationCode: authorizationCode } });
      
      res.redirect(`${redirect_uri}?code=${authorizationCode}`);
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'server_error', error_description: 'Server error' });
  }
});



// Oauth Token endpoint
app.post('/api/oauth/token', async (req, res) => {
  const { code, client_id, client_secret } = req.body;
  try {
    const oauth_client = await oauthClientDB.findOne({ client_id, client_secret });
    const oauth_user = await userDB.findOne({ oauth_authorizationCode: code });
    const oauth_authorizationCode = code;
    await userDB.updateOne({ oauth_authorizationCode }, { $unset: { oauth_authorizationCode: 1 } });
    if (!oauth_client) {
      return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client' });
    }

    if (!oauth_user) {
      return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid authorization code' });
    }
    const userId = oauth_user.userId;
    const sid = oauth_user.sid;

    const oauth_access_token = jwt.sign({ userId: userId, sid: sid }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '48h' });
    const oauth_refresh_token = jwt.sign({ userId: userId }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '96h' });
    res.json({ access_token: oauth_access_token, refresh_token: oauth_refresh_token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'server_error', error_description: 'Server error' });
  }
});



// Added userinfo endpoint
app.post('/api/oauth/userinfo', async (req, res) => {
  const authorizationHeader = req.headers['authorization'];

  if (!authorizationHeader) {
    return res.status(400).json({ error: 'Authorization header is missing' });
  }

  const tokenParts = authorizationHeader.split(' ');
  if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
    return res.status(400).json({ error: 'Invalid authorization header format' });
  }

  const access_token = tokenParts[1];

  try {
    const decoded = jwt.verify(access_token, JWT_SECRET);
    const userId = decoded.userId;
    const sid = decoded.sid;
    
    const userData = await userDB.findOne({ userId: userId, sid: sid });
    if (!userData) {
      res.clearCookie('access_token');
      return res.redirect('/login');
    }

    res.status(200).json({ userId: userId, username: userData.username, email: userData.email });
  } catch (error) {
    notifyError(error)
    return res.status(500).json({ error: 'Something went wrong, try again later' });
  }
});




app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
