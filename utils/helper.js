exports.sendResponse = (res, type, message, statusCode = 401) => {
  res.status(statusCode).json({ [type]: message });
};

exports.handleNotFound = (req, res) => {
  this.sendResponse(res, "error", "This page doesn't exist.", 404);
};
