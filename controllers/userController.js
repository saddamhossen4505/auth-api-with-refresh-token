const User = require("../models/UserModels");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");

/**
 * @desc GET all users
 * @route GET /users
 * @access PUBLIC
 */

const getAllUser = asyncHandler(async (req, res) => {
  const users = await User.find().select("-password").lean();
  if (users?.length > 0) {
    res.status(200).json(users);
  } else {
    res.status(400).json({ message: "No users found." });
  }
});

/**
 * @desc Create User
 * @route POST /user
 * @access PUBLIC
 */
const createUser = asyncHandler(async (req, res) => {
  // GetData.
  const { name, email, role, password } = req.body;

  if (!name || !email || !role || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  // Check email already exits or not.
  const exitsEmail = await User.findOne({ email });

  if (exitsEmail) {
    return res.status(400).json({ message: "Email already exits." });
  }

  // Now create hashPassword.
  const hashPassword = await bcrypt.hash(password, 10);

  // Create User.
  const user = await User.create({ name, email, role, password: hashPassword });

  if (!user) {
    return res.status(400).json({ message: "Invalid user data." });
  } else {
    return res.status(200).json(user);
  }
});

/**
 * @desc Get single user
 * @route GET /user
 * @access PUBLIC
 */
const getSingleUser = asyncHandler(async (req, res) => {
  // Get id
  const { id } = req.params;
  const singleUser = await User.findById(id);
  if (!singleUser) {
    return res.status(400).json({ message: "User not found." });
  } else {
    return res.status(200).json(singleUser);
  }
});

/**
 * @desc delete user data
 * @route DELETE /users/:id
 * @access PUBLIC
 */
const deleteUser = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const user = await User.findByIdAndDelete(id);

  if (!user) {
    return res.status(400).json({ message: "User delete failed" });
  }

  res.json(user);
});

/**
 * @desc update user data
 * @route PATCH /users/:id
 * @access PUBLIC
 */
const updateUser = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const { name, email, password, role } = req.body;

  // validation
  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const user = await User.findById(id).exec();

  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  user.name = name;
  user.email = email;
  user.password = await bcrypt.hash(password, 10);
  user.role = role;

  const updateUserData = await user.save();

  res.json({ message: `User updated successfull`, user: updateUserData });
});

// Export Controllers.
module.exports = {
  getAllUser,
  createUser,
  getSingleUser,
  deleteUser,
  updateUser,
};
