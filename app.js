const express = require("express");
const app = express();
const path = require("path");
const router = express.Router();
const dotenv = require("dotenv/config");
const mongoose = require("mongoose");
const User = require("./models/User");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const session = require("express-session");
const flash = require("express-flash");
const bodyParser = require("body-parser");
const LocalStrategy = require("passport-local").Strategy;
const methodOverride = require("method-override");

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    function (username, password, done) {
      User.findOne({ username: username }, function (err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: "No user with that email." });
        }
        if (!user.validPassword(password)) {
          return done(null, false, { message: "Incorrect password." });
        }
        return done(null, user);
      });
    }
  )
);

//Express middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

//Passport middlewares
app.use(flash());
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

//Middlewares
app.set("views", path.join(__dirname, "/views"));
app.set("view-engine", "ejs");

//Router middlewares
app.use("/", router);

//Connect to DB
mongoose.connect(process.env.DB_CONNECTION, { useUnifiedTopology: true }, () =>
  console.log("Connected to DB !")
);

//GET REQUESTS
router.get("/", checkAuthenticated, (req, res) => {
  res.render("index.ejs", { name: req.body.name });
});

router.get("/login", checkNotAuthenticated, (req, res) => {
  res.render("login.ejs");
});

router.get("/register", checkNotAuthenticated, (req, res) => {
  res.render("register.ejs");
});

//POST REQUESTS
router.post("/register", checkNotAuthenticated, async (req, res) => {
  //Checking if an email already exists in the DB
  const emailExisted = await User.findOne({ email: req.body.email });
  if (emailExisted) res.status(400).send("Email already exists !");

  //Hashing password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  //Creating a new user
  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  });
  try {
    const savedUser = await user.save();
    res.redirect("login");
  } catch (err) {
    res.status(400).send(err);
    res.redirect("register");
  }
});

router.post(
  "/login",
  checkNotAuthenticated,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

//DELETE REQUESTS
app.delete("/logout", (req, res) => {
  req.logOut();
  res.redirect("login");
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect("/login");
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});
