const asyncHandler = require("express-async-handler");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const { sendResponse } = require("../utils/helper");

exports.isAuthenticated = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return sendResponse(res, "error", "Not authorized. Please log in.", 401);
    }

    // Verify token
    const verifiedToken = jwt.verify(token, process.env.JWT_SECRET);
    const { id } = verifiedToken;

    // Get user by id
    const user = await User.findById(id).select("-password");
    if (!user)
      return sendResponse(res, "error", "Invalid token, user not found.", 404);

    if (user.role === "suspended")
      return sendResponse(
        res,
        "error",
        "User suspended. Please contact support.",
        401
      );

    req.user = user;
    next();
  } catch (error) {
    return sendResponse(res, "error", "Not authorized. Please log in.", 401);
  }
});

exports.isAdmin = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    return sendResponse(res, "error", "Not an admin.", 401);
  }
});

exports.isAnAuthor = asyncHandler(async (req, res, next) => {
  if (req.user.role === "author" || req.user.role === "admin") {
    next();
  } else {
    return sendResponse(res, "error", "Not an author, nor an admin.", 401);
  }
});

exports.isVerifiedUser = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isVerified) {
    next();
  } else {
    return sendResponse(res, "error", "Please verify account first.", 401);
  }
});
