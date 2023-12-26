const express = require("express");
const { isAuthenticated } = require("../middlewares/auth");
const {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
} = require("../controllers/user");
const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);

router.get("/logout", logoutUser);
router.get("/get-user", isAuthenticated, getUser);

module.exports = router;
