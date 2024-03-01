const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();

// Update MongoDB connection to allow access from any IP address
mongoose.connect('mongodb://localhost:27017/auth_demo', { useNewUrlParser: true, useUnifiedTopology: true });

const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    firstName: String,
    lastName: String,
    age: Number,
    email: { type: String, unique: true },
    role: { type: String, default: 'user' }
});

const User = mongoose.model('User', UserSchema);

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false
}));
app.use(express.static(path.join(__dirname, 'views')));
app.use('/images', express.static('images'));

// Nodemailer configuration
const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: 'your_acc@gmail.com', // Your Gmail email address
        pass: 'your_pass' // Your Gmail password
    }
});

// Middleware to redirect unauthenticated users to login
const requireLogin = (req, res, next) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
};

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    try {
        const { username, password, firstName, lastName, age, email } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            password: hashedPassword,
            firstName,
            lastName,
            age,
            email
        });
        await newUser.save();

        // Sending welcome message after registration
        const mailOptions = {
            from: 'your_acc@gmail.com', // Your Gmail email address
            to: email, // User's email address
            subject: 'Welcome to our website!',
            text: `Dear ${firstName},\n\nWelcome to our website! We're glad to have you on board.\n\nBest regards,\nToretay`
        };
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        });

        res.redirect('/login');
    } catch (error) {
        res.status(500).send('Error:' + error.message);
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (user && await bcrypt.compare(password, user.password)) {
        req.session.user = user;
        res.redirect('/main');
    } else {
        res.redirect('/login');
    }
});

app.get('/main', requireLogin, (req, res) => {
    res.render('main', { user: req.session.user });
});

app.get('/covid', requireLogin, (req, res) => {
    res.render('covid', { user: req.session.user });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/admin', requireLogin, (req, res) => {
    if (req.session.user.role === 'admin') {
        res.render('admin', { user: req.session.user });
    } else {
        res.redirect('/login');
    }
});

app.post('/delete-account', requireLogin, async (req, res) => {
    try {
        // Get the current user
        const currentUser = req.session.user;
        
        // Delete the user from the database
        await User.findByIdAndDelete(currentUser._id);

        // Sending email to the user
        const mailOptions = {
            from: 'your_acc@gmail.com',
            to: currentUser.email,
            subject: 'Account Deletion Confirmation',
            text: `Dear ${currentUser.firstName},\n\nYour account has been successfully deleted.\n\nBest regards,\nToretay`
        };
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent: ' + info.response);
            }
        });

        // Destroy session and redirect to login page
        req.session.destroy();
        res.redirect('/login');
    } catch (error) {
        res.status(500).send('Error:' + error.message);
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}/login`);
});
