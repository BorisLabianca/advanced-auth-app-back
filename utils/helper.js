const jwt = require("jsonwebtoken");

exports.sendResponse = (res, type, message, statusCode = 401) => {
  res.status(statusCode).json({ [type]: message });
};

exports.handleNotFound = (req, res) => {
  this.sendResponse(res, "error", "This page doesn't exist.", 404);
};

exports.generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};
