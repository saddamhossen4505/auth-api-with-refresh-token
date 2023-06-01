const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");
const User = require("../models/UserModels");

// Create AuthorizationMiddleware.
const authorizationMiddleware = (req, res, next) => {
  // Check authHeaders.
  const authHeader = req.headers.authorization || req.headers.Authorization;

  // Get token.
  const token = authHeader.split(" ")[1];

  // Now verifyToken.
  jwt.verify(
    token,
    process.env.ACCESS_TOKEN_SECRET,
    asyncHandler(async (err, decode) => {
      if (err) {
        return res.status(400).json({ message: "Forbiden token." });
      }
      const me = await User.findOne({ email: decode.email });

      req.me = me;

      next();
    })
  );
};

// Export default.
module.exports = authorizationMiddleware;
