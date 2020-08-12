/* ~~~~~~Encryption~~~~~~
(Good to start encryption before any code run)*/

// require("dotenv").config();

// const encrypt = require("mongoose-encryption"); //I tried combine this with bcrypt to provide 2 layers of encryption for our database and it worked. But I don't how is it good in practice.

// const md5 = require("md5"); //We don't use in this file.

const bcrypt = require("bcryptjs"); //Please note this file use async encryption

const saltRounds = 10; //After some searching, I think it is good to add 1 round for each proceeding year. Just my opition. It all goes down to the time factor.

const express = require("express");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");

app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.listen(3000);

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false, useCreateIndex: true });
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});
// userSchema.plugin(encrypt, { secret: process.env.SECRECT, encryptedFields: ["password"] }); //Must create this plugin before create new mongoose.model because we want to pass the encrypted schema into the new model.

const User = new mongoose.model("User", userSchema);

app.get("/", function (req, res) {
  res.render("home");
});
app.get("/login", function (req, res) {
  res.render("login");
});
app.get("/register", function (req, res) {
  res.render("register");
});

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
