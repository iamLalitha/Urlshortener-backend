require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const passport =require('passport');
const jwt =require('jsonwebtoken');
const nodemailer=require('nodemailer');
const shortid = require('shortid');

const crypto = require('crypto');
const secretKey = process.env.SECRET_KEY;
//console.log(secretKey);

const app = express();
const port=3001;
const User = require('./models/User');
const Url = require('./models/Url');

//middleware
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  const connection = mongoose.connection;
connection.once('open', () => {
  console.log('MongoDB database connection established successfully');
});



// Generate a unique short URL
async function generateUniqueShortURL() {
  let shorturl;
  do {
    // Generate a short ID
    shorturl = shortid.generate();
    // Check if it already exists in the database
    const existingURL = await Url.findOne({ shorturl });
    if (!existingURL) {
      break;
    }
  } while (true);
  return shorturl;
}



// Define your authentication middleware
const authenticateToken = (req, res, next) => {
  // Get the token from the request headers
  const token = req.header('Authorization').split(' ')[1];

  // Check if the token is missing
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Verify the token and extract the user ID
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.error('Token Verification Error:', err);
      return res.status(403).json({ error: 'Forbidden' });
    }
    console.log('Decoded Token Data:', decoded);
    const userId = decoded.userId;
    req.user = decoded; // Set the user object in the request
    next();
  });
};

const transporter =nodemailer.createTransport({
    service:process.env.EMAIL_SERVICE_PROVIDER,
    auth:{
      user:process.env.EMAIL_USER,
      pass:process.env.GMAIL_APP_PASSWORD,
    }
  });

  //To register new user
  app.post('/register', async (req, res) => {
    const { email, password,firstName, lastName } = req.body;
    
    try {
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const newUser = new User({email, password,firstName, lastName, verificationToken});
      console.log(newUser)
      await newUser.save();
  
      // Generate a JWT token
      const token = jwt.sign({ userId: newUser._id }, secretKey, { expiresIn: '1h' });
  
      // Send a verification email
      const emailContent = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Account Activation',
        text: `Click the following link to activate your account: https://gilded-heliotrope-6bfcfd.netlify.app/activate/${verificationToken}`,
    };
    await transporter.sendMail(emailContent);


    res.json({ message: 'User registered! Please check your email to activate your account.', token });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

  app.get('/activate/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const user = await User.findOne({ verificationToken: token });
console.log('User found:', user);
        if (!user) {
            return res.status(404).json({ error: 'Invalid or expired activation token.' });
        }
        console.log('Received token:', token);
      
        user.isVerified = true;
        user.verificationToken = null;
        await user.save();

        res.json({ message: 'Verification successful. You can now log in.' });
    } catch (error) {
      console.log('Error:', error);
        res.status(500).json({ error: 'An error occurred while processing the request' });
    }
});


// User login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (!user.isVerified) {
        return res.status(403).json({ error: 'Account not activated. Please check your email to activate your account.' });
    }
  
      // Compare hashed password
      if (user.password !== password) {
        return res.status(400).json({ error: 'Invalid password' });
      }
  
      // Generate a JWT token
      const token = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });
  
      const user_name =  user.email
      const user_id = user._id
  
      res.json({ message: 'Login successful', token , username : user_name , userid :  user_id }); // Return the token
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

//forgot password

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      const verificationToken = jwt.sign({ userId: user._id }, secretKey, { expiresIn: '1h' });
      user.verificationToken = verificationToken;
      await user.save();
  
      const emailContent = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Password Reset Verification',
        text: `Click the following link to verify your password reset:  https://gilded-heliotrope-6bfcfd.netlify.app/reset-password/${verificationToken}`,
      };
     
      await transporter.sendMail(emailContent);
  
      res.json({ message: 'Verification email sent successfully' });
    } catch (error) {
      console.error('Send verification email error:', error);
      res.status(500).json({ error: 'An error occurred while sending the verification email'});
    }
  });

//reset password
app.post('/reset-password/:token', async (req, res) => {
  const { token} =req.params;
  const{newPassword} =req.body;
  try {
    const decodedToken = jwt.verify(token, secretKey);
    const user = await User.findOne({ _id: decodedToken.userId })
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.password = newPassword;
    user.verificationToken = null; 
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'An error occurred while processing the request' });
  }
});



//url routes

// URL Shortening Endpoint
app.post('/shorten', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id; 

    const { originalURL, title} = req.body;

    // Generate a unique short URL
    const shorturl = await generateUniqueShortURL();

    const newURL = new Url({
      title: title,
      longurl: originalURL,
      shorturl,
      user: userId,
    });

    await newURL.save();

    res.status(201).json({ shorturl: newURL.shorturl });
  } catch (error) {
    console.error('Error creating URL:', error);
    res.status(500).json({ error: 'An error occurred while creating the URL' });
  }
});

// Get URLs created by the user
app.get('/urls/user', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;

    const userURLs = await Url.find({ user: userId }).populate('user').select('title longurl shorturl shortid clicks createdon');

    res.status(200).json(userURLs);
  } catch (error) {
    console.error('Error fetching user URLs:', error);
    res.status(500).json({ error: 'An error occurred while fetching user URLs' });
  }
});



// Redirect short URL
app.get('/:shorturl', async (req, res) => {
  try {
    const { shorturl } = req.params;

    // Find the URL in the database
    const url = await Url.findOne({ shorturl });

    if (!url) {
      return res.status(404).json({ error: 'Short URL not found' });
    }

    // Update clicks count
    url.clicks += 1;
    await url.save();

    // Redirect to the long URL
    res.redirect(url.longurl);
  } catch (error) {
    console.error('Error redirecting short URL:', error);
    res.status(500).json({ error: 'An error occurred while redirecting the URL' });
  }
});


  app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
  });
