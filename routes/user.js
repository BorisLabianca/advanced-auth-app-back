const express = require("express");
const { isAuthenticated, isAdmin, isAnAuthor } = require("../middlewares/auth");
const fileUpload = require("express-fileupload");
const {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  updateUser,
  deleteUser,
  getAllUsers,
  loginStatus,
  upgradeUser,
  sendAutomatedEmail,
  sendVerificationEmail,
  verifyUser,
  forgotPassword,
  resetPassword,
  changePassword,
  sendLoginCode,
  loginWithCode,
  loginWithGoogle,
} = require("../controllers/user");

const router = express.Router();

router.post("/register", registerUser);
router.post("/login", loginUser);
router.post("/send-automated-email", isAuthenticated, sendAutomatedEmail);
router.post("/send-verification-email", isAuthenticated, sendVerificationEmail);
router.post("/forgot-password/", forgotPassword);
router.post("/send-login-code/:email", sendLoginCode);
router.post("/login-with-code/:email", loginWithCode);
// Google login
router.post("/google/callback", loginWithGoogle);

router.get("/logout", logoutUser);
router.get("/get-user", isAuthenticated, getUser);
router.get("/get-all-users", isAuthenticated, isAnAuthor, getAllUsers);
router.get("/login-status", loginStatus);

router.patch("/update-user", isAuthenticated, fileUpload(), updateUser);
router.patch("/verify-user/:verificationToken", verifyUser);
router.patch("/reset-password/:passwordResetToken", resetPassword);
router.patch("/change-password/", isAuthenticated, changePassword);
router.patch("/upgrade-user", isAuthenticated, isAdmin, upgradeUser);

router.delete("/delete/:id", isAuthenticated, isAdmin, deleteUser);

module.exports = router;
