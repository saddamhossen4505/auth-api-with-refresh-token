const asyncHandler = require("express-async-handler");
const User = require("../models/UserModels");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

/**
 * @desc User login system
 * @route POST /user/login
 * @access PUBLIC
 */

const loginUser = asyncHandler(async (req, res) => {
  // Get loginUserData.
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  // Chect User.
  const isUser = await User.findOne({ email });

  if (!isUser) {
    return res.status(400).json({ message: "User not found." });
  }

  // Password Check.
  const isValidPassword = await bcrypt.compare(password, isUser.password);

  if (!isValidPassword) {
    return res.status(400).json({ message: "Invalid password." });
  }

  // Create an accessToken.
  const accessToken = jwt.sign(
    { email: isUser.email },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
    }
  );

  // Create an refreshToken.
  const refreshToken = jwt.sign(
    { email: isUser.email },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN,
    }
  );

  // Access token save to cookie memory.
  res.cookie("rToken", refreshToken, {
    httpOnly: true,
    secure: false,
    maxAge: 1000 * 60 * 60 * 24 * 7,
  });

  res.json({ token: accessToken });
});

/**
 * @desc Refresh token request
 * @route GET /user/refresh
 * @access PUBLIC
 */

const getRefreshToken = (req, res) => {
  // Cheack cookies.
  const cookies = req.cookies;
  if (!cookies?.rToken) {
    return res.status(400).json({ message: "No cookies found." });
  }

  // Get token.
  const token = cookies.rToken;

  jwt.verify(
    token,
    process.env.REFRESH_TOKEN_SECRET,
    asyncHandler(async (err, decode) => {
      if (err) {
        return res.status(400).json({ message: "Invalid token." });
      }

      // CheckUser.
      const tokenUser = await User.findOne({ email: decode.email });
      if (!tokenUser) {
        return res.status(400).json({ message: "User not found." });
      }

      // Create an accessToken.
      const accessToken = jwt.sign(
        { email: tokenUser.email },
        process.env.ACCESS_TOKEN_SECRET,
        {
          expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN,
        }
      );

      res.json({ token: accessToken });
    })
  );
};

// Export controllers.
module.exports = {
  loginUser,
  getRefreshToken,
};
