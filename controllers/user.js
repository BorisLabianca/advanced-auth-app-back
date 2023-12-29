const asyncHandler = require("express-async-handler");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const parser = require("ua-parser-js");
const { sendResponse, generateToken } = require("../utils/helper");

// Sing up
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

  // Get user agent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];
  // Create new user
  const user = await User.create({ name, email, password, userAgent });

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

// Login
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    return sendResponse(
      res,
      "error",
      "Both the email and the password are needed.",
      401
    );
  }
  const user = await User.findOne({ email });

  if (!user) {
    return sendResponse(
      res,
      "error",
      "User not found. Please create an account.",
      401
    );
  }

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    return sendResponse(res, "error", "Invalid email or password.", 401);
  }

  // Trigger two factor authentication for unknown userAgent

  const token = generateToken(user._id);
  if (user && passwordIsCorrect) {
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400),
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    sendResponse(
      res,
      "user",
      { _id, name, email, phone, bio, photo, role, isVerified, token },
      200
    );
  } else {
    sendResponse(res, "error", "Something went wrong. Please try again.", 500);
  }
});

// Logout
const logoutUser = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });

  return sendResponse(res, "success", "User successfully logged out.", 200);
});

// Get user info
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    sendResponse(
      res,
      "user",
      { _id, name, email, phone, bio, photo, role, isVerified },
      200
    );
  } else {
    sendResponse(res, "error", "User not found.", 404);
  }
});

// Update user

const updateUser = asyncHandler(async (req, res) => {
  if (!req.body.name && !req.body.phone && !req.body.bio && !req.body.photo)
    return sendResponse(
      res,
      "error",
      "Please update at least one piece of information.",
      400
    );

  const user = await User.findById(req.user._id);
  if (user) {
    const { name, phone, bio, photo } = user;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;
    user.photo = req.body.photo || photo;

    const updatedUser = await user.save();
    sendResponse(
      res,
      "user",
      {
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        phone: updatedUser.phone,
        bio: updatedUser.bio,
        photo: updatedUser.photo,
        role: updatedUser.role,
        isVerified: updatedUser.isVerified,
      },
      200
    );
  } else {
    sendResponse(res, "error", "User not found.", 404);
  }
});

const deleteUser = asyncHandler(async (req, res) => {});

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
};
