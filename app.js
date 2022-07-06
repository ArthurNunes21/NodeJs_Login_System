const express = require("express");
const session = require("express-session");
const hbs = require("express-handlebars");
const mongoose = require("mongoose");
const passport = require("passport");
const localStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const app = express();

//----------Database Connection---------//
mongoose.connect("mongodb+srv://root:12345@cluster0.cpj5ya3.mongodb.net/?retryWrites=true&w=majority",{
    useNewUrlParser: true,
    useUnifiedTopology:true
});

const UserSchema  = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
})
const User = mongoose.model('User', UserSchema)



// Middleware
app.engine('hbs', hbs.engine({extname: 'hbs'}));
app.set('view engine', 'hbs');
app.use(express.static(__dirname + '/public'));
app.use(session({
	secret: "thesecret",
	resave: false,
	saveUninitialized: true
}));
app.use(express.urlencoded({extended:false}));
app.use(express.json());

//--Passport.js--//
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user,done)=>{
    done(null, user.id);
});
passport.deserializeUser((id,done)=>{
    //Setting Up user model
    User.findById(id, (err,user)=>{
        done(err, user);
    });
});
passport.use(new localStrategy(function(username,password,done){

    //Veryfing if User is Correct//
    User.findOne({username: username},function(err,user){
        if(err){return done(err);}
        if(!user){return done(null, false, { message:'Incorrect Username, try again'});}
        
        //Veryfing if User's Password is Correct//
        bcrypt.compare(password, user.password, function(err, res){
            if(err)return done(err);
            if(res === false){return done(null, false, { message: 'Incorrect Password, try again'});}
            return done(null, user);
        });
    });
}));

function isLoggedIn(req, res, next){
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}
function isLoggedOut(req, res, next){
    if (!req.isAuthenticated()) return next();
    res.redirect('/');
}
//Setting up our admin User//
app.get('/setup', async (req,res)=>{
    const exists = await User.exists({username: "admin"});
    if(exists){
        res.redirect('/login');
        return;
    }
    bcrypt.genSalt(10, function(err,salt){
        if(err)return next(err);
        bcrypt.hash("password", salt, function(err,hash){
            if(err) return next(err);
            const newAdmin = new User({
                username: "admin",
                password: hash
            });
            newAdmin.save();
            res.redirect('/login');
        });
    });
});

//--Routes--//
app.get('/', isLoggedIn, (req,res)=>{
    res.render('index',{title:"Home"});
});
app.get('/login', isLoggedOut,(req,res)=>{
    const response = {
        title: "Login",
        error: req.query.error
    }
    res.render('login', response);
});
app.listen(8080,()=>{
    console.log("Server is running on port 8080");
});
app.post('/login', passport.authenticate('local',{
    successRedirect: '/',
    failureRedirect: '/login?error=true'
}));
app.get("/logout", function (req, res) {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/");
    });
  });