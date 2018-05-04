// module imports
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3');
const Sequelize = require('sequelize');
const crypto = require('crypto');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const app = express();
const router = express.Router();
const handlebars = require("express-handlebars").create({ defaultLayout: 'main' });
app.engine('handlebars', handlebars.engine);
app.set('view engine', 'handlebars');

// body parser config;
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: true
}));
 
// connect to db

const sequelize = new Sequelize('database', 'username', 'password',  {
    host: 'localhost',
    dialect: 'sqlite',
    storage: "./Chinook_Sqlite_AutoIncrementPKs.sqlite"
});


// define schema
const User = sequelize.define('User', {
    ID: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
        firstName: Sequelize.STRING,
        lastName: Sequelize.STRING,
        username: Sequelize.STRING,
        passwordHash: Sequelize.STRING,
        salt: Sequelize.STRING
},
{
    freezeTableName: true,
    timestamps: false
})


const Post = sequelize.define('message', {
    ID: {
        type: Sequelize.INTEGER,
        
    },
    authorID: {type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },

    message: Sequelize.STRING,
}, 
 
{
    freezeTableName: true,
    timestamps: true
})

User.sync({force: false});
Post.sync({force: false});

// auth config
app.use(passport.initialize());

passport.serializeUser(function(user, done){
    done(null, user);
});
  
passport.deserializeUser(function(obj, done){
    done(null, obj);
});


passport.use(new LocalStrategy(function(username, password, done){
    User.findOne({ where: {username: username} }).then(user => { 
        let salt = crypto.randomBytes(16).toString('hex');
        let passwordHash = crypto.pbkdf2Sync(password, user.salt, 1000, 64, 'sha1').toString('hex');

        if(!user){
            return done(null, false, {message: "Invalid user"});
        } else if(passwordHash !== user.passwordHash) {
            return done(null, false, {message: 'Incorrect password'});
        } else {
            return done(null, user);
        }
    })
}));
    
app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
}),



// API
app.get('/', (req, res) => {
    res.render('signup')
}),


app.get('/login', (req, res, next) => {
    res.render('login')
}),

app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login' }),
  function(req, res, next) {
    res.redirect('home');
}),

app.get('/home', (req, res,next) => {
    res.render('home')
}),

app.get('/signup', (req, res, next) => {
	res.render('signup')
}),

app.post('/signup', (req, res) => {
    let salt = crypto.randomBytes(16).toString('hex');
    let passwordHash = crypto.pbkdf2Sync(req.body.password, salt, 1000, 64, 'sha1').toString('hex');

    User.create({
        
        firstName: req.body.firstName,
        lastName:  req.body.lastName,
        username: req.body.username,
        passwordHash: passwordHash,
        salt: salt
    })
    res.render('home')
}),


app.get('/message', (req, res) => {
	res.render('message')
})

app.post('/message', (req, res) => {

    Post.create({
        
        authorID: req.User,
        message:  req.body.message,
        timestamp: req.datetime-local   
    })
    if (err) throw err;
    res.redirect(303, '/success');
    res.render('post')
}),

app.get('/post', (req, res) => {
	res.render('post')
})

app.post('/post', (req, res) => {
	res.render('post')
})

//run server on port 8080
app.listen(8080, () => {
    console.log('server running')}
)
