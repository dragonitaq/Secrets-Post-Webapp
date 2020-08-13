/* ~~~~~~Encryption~~~~~~
(Good to start encryption before any code run)*/

// require("dotenv").config();

// const encrypt = require("mongoose-encryption"); //I tried combine this with bcrypt to provide 2 layers of encryption for our database and it worked. But I don't how is it good in practice.

// const md5 = require("md5"); //We don't use in this file.

// const bcrypt = require("bcryptjs"); //Please note this file use async encryption

// const saltRounds = 10; //After some searching, I think it is good to add 1 round for each proceeding year. Just my opition. It all goes down to the time factor.

const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.listen(3000);

app.use(
  session({
    secret: "toBeAssigned",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize()); //Passport must be initialized before calling any "passport.<function>"
app.use(passport.session()); //Session must be created before serialize/deserialize cookie.

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false, useCreateIndex: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

// userSchema.plugin(encrypt, { secret: process.env.SECRECT, encryptedFields: ["password"] });
//Must create this plugin before create new mongoose.model because we want to pass the encrypted schema into the new model.

userSchema.plugin(passportLocalMongoose); //This will salt & hash our database.
//Again, we must create this plugin before create new mongoose.model because we want to pass the encrypted schema into the new model.

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser()); //Generate cookie
passport.deserializeUser(User.deserializeUser()); //Digest cookie

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/secrets", function (req, res) {
  /*I read somewhere the return value is Boolean for "isAuthenticated()", don't we need to check true/false? like this:
  if (req.isAuthenticated() === true) */
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", function (req, res) {
  //Because we use passport-local-mongoose, we can now use ".register" method.
  User.register({ username: req.body.username }, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect("register");
    } else {
      // Codes very are confusing. Dr Angela Yu didn't explain.
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Daniel's version~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/* Below codes are from Daniel which is correct. Because we authenticate user once we receive informatoin. He said ".authenticate()" will automatically log use in. */
// app.post("/login", passport.authenticate("local"), function(req, res){
//   res.redirect("/secrets");
// });

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Nestor's version~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/* Below codes are from Nestor which is also correct. It is longer because he search pull data from database then only authenticate the user. He also redirect use to login page when error.*/
app.post("/login", function(req, res){
  //check the DB to see if the username that was used to login exists in the DB
  User.findOne({username: req.body.username}, function(err, foundUser){
    //if username is found in the database, create an object called "user" that will store the username and password
    //that was used to login
    if(foundUser){
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
      //use the "user" object that was just created to check against the username and password in the database
      //in this case below, "user" will either return a "false" boolean value if it doesn't match, or it will
      //return the user found in the database
      passport.authenticate("local", function(err, user){
        if(err){
          console.log(err);
        } else {
          //this is the "user" returned from the passport.authenticate callback, which will be either
          //a false boolean value if no it didn't match the username and password or
          //a the user that was found, which would make it a truthy statement
          if(user){
            //if true, then log the user in, else redirect to login page
            req.login(user, function(err){
            res.redirect("/secrets");
            });
          } else {
            res.redirect("/login");
          }
        }
      })(req, res);
    //if no username is found at all, redirect to login page.
    } else {
      //user does not exists
      res.redirect("/login")
    }
  });
});

/* Below codes are from Angela which is WRONG. Because we straight away login() user with authenticate first. */
// app.post("/login", function (req, res) {
//   const user = new User({
//     username: req.body.username,
//     password: req.body.password,
//   });
//   //login() is function from passport.
//   req.logIn(user, function (err) {
//     if (err) {
//       console.log(err);
//     } else {
//       passport.authenticate("local")(req, res, function () {
//         res.redirect("/secrets");
//       });
//     }
//   });
// });

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~Below handle bcrypt~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*  
app.post("/register", function (req, res) {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash,
    });
    newUser.save(function (err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });
});

app.post("/login", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;
  User.findOne({ email: username }, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function (err, result) {
          if (result === true) {
            res.render("secrets");
          } else {
            res.send("Wrong password.");
          }
        });
      } else {
        res.send("Email not registered.");
      }
    }
  });
});
*/
