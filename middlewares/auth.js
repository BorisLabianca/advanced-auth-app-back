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
