equire("dotenv").config();

const express = require("express");

const app = express();

const ejs = require("ejs");

const bodyParser = require("body-parser");

const mongoose = require("mongoose");

const session = require("express-session");

const passport = require("passport");

const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require("passport-google-oauth20").Strategy;

const FacebookStrategy = require("passport-facebook").Strategy;

const findOrCreate = require("mongoose-findorcreate");

app.set("view engine", "ejs");

app.use(express.static("public"));

app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: "Ourlittlesecret",

    resave: false,

    saveUninitialized: false,
  })
);

app.use(passport.initialize());

app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true });

mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,

  password: String,

  googleId: String, //to store the google id  of the user to find or create their details in the database

  facebookId: String, //to store the facebook id  of the user to find or create their details in the database
});

userSchema.plugin(passportLocalMongoose);

userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//Serializing and deserializing the user using passport's methods

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

//to create a new google strategy

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,

      clientSecret: process.env.CLIENT_SECRET,

      callbackURL: "http://localhost:3000/auth/google/secrets",

      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },

    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);

      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//using a new facebook strategy

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.APP_ID,

      clientSecret: process.env.APP_SECRET,

      callbackURL: "http://localhost:3000/auth/facebook/secrets",
    },

    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google", //this is for authentication by google

  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets", //this is for authentication locally

  passport.authenticate("google", { failureRedirect: "/login" }),

  function (req, res) {
    // Successful authentication, redirect home.

    res.redirect("/secrets");
  }
);

app.get(
  "/auth/facebook",

  passport.authenticate("facebook") //Notice there is no {scope: ["profile"]} here.
);

app.get(
  "/auth/facebook/secrets",

  passport.authenticate("facebook", { failureRedirect: "/login" }),

  function (req, res) {
    // Successful authentication, redirect home.

    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout();

  res.redirect("/");
});

app.post("/register", function (req, res) {
  User.register({ username: req.body.username }, req.body.password, function (err, user) {
    if (err) {
      console.log(err);

      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,

    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function () {
  console.log("Server is up and running on port 3000");
});
