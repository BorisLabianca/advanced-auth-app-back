const express = require("express");
const { isAuthenticated, isAdmin, isAnAuthor } = require("../middlewares/auth");
const {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getAllUsers,
} = require("../controllers/user");
const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);

router.get("/logout", logoutUser);
router.get("/get-user", isAuthenticated, getUser);
router.get("/get-all-users", isAuthenticated, isAnAuthor, getAllUsers);

router.patch("/update-user", isAuthenticated, updateUser);

router.delete("/delete/:id", isAuthenticated, isAdmin, deleteUser);

module.exports = router;
