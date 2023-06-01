const express = require("express");
const {
  loginUser,
  getRefreshToken,
} = require("../controllers/loginUserController");

// Init router.
const router = express.Router();

// Routes.
router.route("/login").post(loginUser);
router.route("/refresh").get(getRefreshToken);

// Export router.
module.exports = router;
