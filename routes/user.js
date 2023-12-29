const express = require("express");
const { isAuthenticated, isAdmin } = require("../middlewares/auth");
const {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
} = require("../controllers/user");
const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);

router.get("/logout", logoutUser);
router.get("/get-user", isAuthenticated, getUser);

router.patch("/update-user", isAuthenticated, updateUser);

router.delete("/delete/:id", isAuthenticated, isAdmin, deleteUser);

module.exports = router;
