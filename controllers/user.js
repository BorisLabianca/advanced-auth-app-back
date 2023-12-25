const { sendResponse } = require("../utils/helper");

const registerUser = (req, res) => {
  sendResponse(res, "message", "Register user", 201);
};

module.exports = { registerUser };
