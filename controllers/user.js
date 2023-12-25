const asyncHandler = require("express-async-handler");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const { sendResponse, generateToken } = require("../utils/helper");

const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  // Validation
  if (!name || !email || !password) {
    return sendResponse(res, "error", "Please fill in all the fields.", 400);
  }

  if (password.length < 8) {
    return sendResponse(
      res,
      "error",
      "Password must be at least 8 characters long.",
      400
    );
  }

  // Check if user exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    return sendResponse(res, "error", "Email already used.", 409);
  }

  // Create new user
  const user = await User.create({ name, email, password });

  // Generate token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400),
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    sendResponse(
      res,
      "user",
      { _id, name, email, phone, bio, photo, role, isVerified, token },
      201
    );
  } else {
    sendResponse(res, "error", "Invalid user data", 400);
  }
});

module.exports = { registerUser };
