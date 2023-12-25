exports.errorHandler = (err, req, res, next) => {
  const statusCode = res.statusCode ? res.statusCode : 500;
  console.log("error: ", err);
  res
    .status(statusCode)
    .json({
      error: err.message || err,
      stack: process.env.NODE_ENV === "development" ? err.stack : null,
    });
};
