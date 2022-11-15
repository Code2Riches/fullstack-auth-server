var express = require("express");
var router = express.Router();
const { uuid } = require("uuidv4");
const { db } = require("../mongo");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

let user = {};

/* GET users listing. */
router.get("/", function (req, res, next) {
  res.send("respond with a resource");
});

/* POST Register Users. */
router.post("/registration", async (req, res, next) => {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const saltRounds = 5; // For prod apps, saltRounds are going to be between 5 and 10
    const salt = await bcrypt.genSalt(saltRounds);
    const passwordHash = await bcrypt.hash(password, salt);

    user = {
      email: email,
      password: passwordHash,
      id: uuid(), // uid stands for User ID. This will be a unique string that we will use to identify our user
    };

    const insertResult = await db().collection("users").insertOne(user);
    res.json({
      success: true,
      message: "User registered successfully",
      insertResult,
    });
  } catch (err) {
    console.log(err);
    res.json({
      success: false,
      error: err.toString(),
    });
  }
});

/* POST User Login */
router.post("/login", async (req, res, next) => {
  try {
    const email = req.body.email;
    const password = req.body.password;
    const user = await db().collection("users").findOne({ email });

    if (!user) {
      res.json({ success: false, message: "Could not find user." }).status(204);
      return;
    }
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      res
        .json({ success: false, message: "Password was incorrect." })
        .status(204);
      return;
    }

    const userType = email.includes("codeimmersives.com") ? "admin" : "user";

    const userData = {
      date: new Date(),
      userId: user.id,
      scope: userType,
    };
    const exp = Math.floor(Date.now() / 1000) + 60 * 60;
    const payload = {
      userData,
      exp,
    }
    const jwtSecretKey = process.env.JWT_SECRET_KEY;
    const token = jwt.sign(payload, jwtSecretKey);
    res.json({ 
      success: true, 
      token, 
      email, 
    });
  } catch (err) {
    console.log(err);
    res.json({
      success: false,
      error: err.toString(),
    });
  }
});

module.exports = router;
