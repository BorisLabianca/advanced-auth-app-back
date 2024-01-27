const asyncHandler = require("express-async-handler");
const User = require("../models/User");
const Token = require("../models/Token");
const bcrypt = require("bcryptjs");
const parser = require("ua-parser-js");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Cryptr = require("cryptr");
const { sendResponse, generateToken, hashToken } = require("../utils/helper");
const { isValidObjectId } = require("mongoose");
const { sendEmail } = require("../utils/sendEmail");
const cloudinary = require("cloudinary").v2;

const cryptr = new Cryptr(process.env.CRYPTR_SECRET_KEY);

// Sing up
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  // Validation
  if (!name || !email || !password) {
    return sendResponse(res, "error", "Please fill in all the fields.", 400);
  }

  if (password.length < 8) {
    return sendResponse(
      res,
      "error",
      "Password must be at least 8 characters long.",
      400
    );
  }

  // Check if user exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    return sendResponse(res, "error", "Email already used.", 409);
  }

  // Get user agent
  const ua = parser(req.headers["user-agent"]);
  const userAgent = [ua.ua];
  // Create new user
  const user = await User.create({ name, email, password, userAgent });

  // Generate token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400),
    sameSite: "none",
    secure: true,
  });

  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    sendResponse(
      res,
      "user",
      { _id, name, email, phone, bio, photo, role, isVerified, token },
      201
    );
  } else {
    sendResponse(res, "error", "Invalid user data", 400);
  }
});

// Send verification email
const sendVerificationEmail = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select("-password");
  if (!user) return sendResponse(res, "error", "User not found.", 404);
  if (user.isVerified)
    return sendResponse(res, "error", "User already verified.", 400);

  // Delete token if there already one for this user
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // Create verification token and save it
  const verificationToken = crypto.randomBytes(32).toString("hex") + user._id;

  // Hash token and save it
  const hashedToken = hashToken(verificationToken);
  await new Token({
    userId: user._id,
    verificationToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000),
  }).save();

  // Construct verification url
  const verificationUrl = `${process.env.FRONT_END_URL}/verify/${verificationToken}`;
  // console.log(verificationToken);

  // Send verification email
  const subject = "Verify your AdvAUTH account";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@advauth.com";
  const template = "verifyEmail";
  const name = user.name;
  const link = verificationUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    sendResponse(res, "message", "Verification email successfully sent.", 200);
  } catch (error) {
    sendResponse(res, "error", "Email not sent. Please try again.", 500);
  }
});

// Verify user
const verifyUser = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;
  if (!verificationToken)
    return sendResponse(res, "error", "No verification token found.", 400);

  const hashedToken = hashToken(verificationToken);
  const userToken = await Token.findOne({
    verificationToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken)
    return sendResponse(res, "error", "Token is invalid or expired.", 404);

  const user = await User.findOne({ _id: userToken.userId });

  if (user.isVerified)
    return sendResponse(res, "error", "User already verified.", 400);

  user.isVerified = true;

  await user.save();

  sendResponse(res, "message", "Account verification successful.", 200);
});

// Login
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    return sendResponse(
      res,
      "error",
      "Both the email and the password are needed.",
      401
    );
  }
  const user = await User.findOne({ email });

  if (!user) {
    return sendResponse(
      res,
      "error",
      "User not found. Please create an account.",
      401
    );
  }

  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  if (!passwordIsCorrect) {
    return sendResponse(res, "error", "Invalid email or password.", 401);
  }

  // Trigger two factor authentication for unknown userAgent
  const ua = parser(req.headers["user-agent"]);
  const thisUserAgent = ua.ua;
  const savedAgent = user.userAgent.includes(thisUserAgent);
  if (!savedAgent) {
    const loginCode = Math.floor(100000 + Math.random() * 900000);
    const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

    let userToken = await Token.findOne({ userId: user._id });
    if (userToken) {
      await userToken.deleteOne();
    }

    await new Token({
      userId: user._id,
      loginToken: encryptedLoginCode,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60 * (60 * 1000),
    }).save();

    return sendResponse(
      res,
      "warning",
      "New device detected. Please check your email for login code.",
      400
    );
  }

  const token = generateToken(user._id);
  if (user && passwordIsCorrect) {
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400),
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    sendResponse(
      res,
      "user",
      { _id, name, email, phone, bio, photo, role, isVerified, token },
      200
    );
  } else {
    sendResponse(res, "error", "Something went wrong. Please try again.", 500);
  }
});

const sendLoginCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const user = await User.findOne({ email });
  if (!user) return sendResponse(res, "error", "User not found.", 404);

  const loginToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });

  if (!loginToken)
    return sendResponse(
      res,
      "error",
      "Token is invalid or has expired. Please log in again.",
      404
    );
  const loginCode = loginToken.loginToken;
  if (!loginCode)
    return sendResponse(
      res,
      "error",
      "Login token not found. Please log in again.",
      404
    );

  const decryptedLoginCode = cryptr.decrypt(loginCode);
  const subject = "Login Access Code - AdvAUTH account";
  const send_to = email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@advauth.com";
  const template = "loginCode";
  const name = user.name;
  const link = decryptedLoginCode;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    sendResponse(res, "message", `A login code has been sent to ${email}`, 200);
  } catch (error) {
    sendResponse(res, "error", "Email not sent. Please try again.", 400);
  }
});

const loginWithCode = asyncHandler(async (req, res) => {
  const { email } = req.params;
  const { loginCode } = req.body;

  const user = await User.findOne({ email });
  if (!user) return sendResponse(res, "error", "User not found.", 404);

  const userToken = await Token.findOne({
    userId: user._id,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken)
    return sendResponse(res, "error", "Token is invalid or has expired.", 404);

  const decryptedToken = cryptr.decrypt(userToken.loginToken);
  if (decryptedToken !== loginCode) {
    return sendResponse(
      res,
      "error",
      "Invalid login code. Please try again.",
      400
    );
  } else {
    const ua = parser(req.headers(["user-agent"]));
    const thisUserAgent = ua.ua;
    user.userAgent.push(thisUserAgent);
    await user.save();

    const token = generateToken(user._id);
    res.cookie("token", token, {
      path: "/",
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400),
      sameSite: "none",
      secure: true,
    });

    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    sendResponse(
      res,
      "user",
      { _id, name, email, phone, bio, photo, role, isVerified, token },
      200
    );
  }
});

// Logout
const logoutUser = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });

  return sendResponse(res, "success", "User successfully logged out.", 200);
});

// Get user info
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  if (user) {
    const { _id, name, email, phone, bio, photo, role, isVerified } = user;
    sendResponse(
      res,
      "user",
      { _id, name, email, phone, bio, photo, role, isVerified },
      200
    );
  } else {
    sendResponse(res, "error", "User not found.", 404);
  }
});

// Update user

const updateUser = asyncHandler(async (req, res) => {
  if (!req.body.name && !req.body.phone && !req.body.bio && !req.body.photo)
    return sendResponse(
      res,
      "error",
      "Please update at least one piece of information.",
      400
    );
  const convertToBase64 = (file) => {
    return `data:${file?.mimetype};base64,${file.data.toString("base64")}`;
  };
  // console.log(req.files?.photo.mimetype);
  const user = await User.findById(req.user._id);

  if (user) {
    if (req.files?.photo) {
      if (
        !user.photo.url ||
        user.photo.url ===
          "https://res.cloudinary.com/dbe27rnpk/image/upload/v1703515550/advancedAuth/user/avatar_vmxetj.png"
      ) {
        const { secure_url: url, public_id } = await cloudinary.uploader.upload(
          convertToBase64(req.files.photo),
          {
            folder: `/advancedAuth/user/${user._id}`,
          }
        );
        user.photo = { url, public_id };
      } else {
        console.log("From else: ", user.photo);
        await cloudinary.uploader.destroy(user.photo.public_id);
        const { secure_url: url, public_id } = await cloudinary.uploader.upload(
          convertToBase64(req.files.photo),
          {
            folder: `/advancedAuth/user/${user._id}`,
          }
        );
        user.photo = { url, public_id };
      }
    }
    const { name, phone, bio } = user;
    user.name = req.body.name || name;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;

    const updatedUser = await user.save();
    sendResponse(
      res,
      "user",
      {
        _id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email,
        phone: updatedUser.phone,
        bio: updatedUser.bio,
        photo: updatedUser.photo,
        role: updatedUser.role,
        isVerified: updatedUser.isVerified,
      },
      200
    );
  } else {
    sendResponse(res, "error", "User not found.", 404);
  }
});

const deleteUser = asyncHandler(async (req, res) => {
  if (!isValidObjectId(req.params.id))
    return sendResponse(res, "error", "Invalid user id.");
  const user = await User.findById(req.params.id);
  if (!user) return sendResponse(res, "error", "User not found.", 404);

  await User.deleteOne({ _id: req.params.id });
  sendResponse(res, "message", "User deleted successfully.", 200);
});

const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find().sort("-createdAt").select("-password");
  if (!users)
    return sendResponse(res, "error", "There no users in the database.", 400);

  sendResponse(res, "users", users, 200);
});

const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }

  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  }

  return res.json(false);
});

const upgradeUser = asyncHandler(async (req, res) => {
  const { id, role } = req.body;
  if (!id) return sendResponse(res, "error", "User id is needed.", 400);
  if (!role) return sendResponse(res, "error", "User role is needed.", 400);

  if (!isValidObjectId(id))
    return sendResponse(res, "error", "Invalid user id.");

  const user = await User.findById(id);
  if (!user) return sendResponse(res, "error", "User not found.", 400);
  if (user.role === role)
    return sendResponse(res, "error", "User role must be different.", 400);

  user.role = role;
  await user.save();

  sendResponse(res, "message", `User role updated to ${role}.`, 200);
});

const sendAutomatedEmail = asyncHandler(async (req, res) => {
  const { subject, send_to, reply_to, template, url } = req.body;
  if (!subject || !send_to || !reply_to || !template)
    return sendResponse(res, "error", "Missing parameters.", 400);

  const user = await User.findOne({ email: send_to });
  if (!user) return sendResponse(res, "error", "User not found.", 404);

  const sent_from = process.env.EMAIL_USER;
  const name = user.name;
  const link = `${process.env.FRONT_END_URL}${url}`;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    sendResponse(res, "message", "Email successfully sent.", 200);
  } catch (error) {
    sendResponse(res, "error", "Email not sent. Please try again.", 500);
  }
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) return sendResponse(res, "error", "User not found.", 404);

  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  const resetToken = crypto.randomBytes(32).toString("hex") + user._id;

  const hashedToken = hashToken(resetToken);
  await new Token({
    userId: user._id,
    passwordResetToken: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 60 * (60 * 1000),
  }).save();

  const resetUrl = `${process.env.FRONT_END_URL}/reset-password/${resetToken}`;

  const subject = "Password Reset Request - AdvAUTH account";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;
  const reply_to = "noreply@advauth.com";
  const template = "forgotPassword";
  const name = user.name;
  const link = resetUrl;

  try {
    await sendEmail(
      subject,
      send_to,
      sent_from,
      reply_to,
      template,
      name,
      link
    );
    sendResponse(res, "message", "Password reset email sent.", 200);
  } catch (error) {
    sendResponse(res, "error", "Email not sent. Please try again.", 400);
  }
});

const resetPassword = asyncHandler(async (req, res) => {
  const { passwordResetToken } = req.params;
  const { password } = req.body;
  if (!passwordResetToken || !password)
    return sendResponse(res, "error", "Missing parameters.", 200);

  if (password.length < 8) {
    return sendResponse(
      res,
      "error",
      "Password must be at least 8 characters long.",
      400
    );
  }

  const hashedToken = hashToken(passwordResetToken);

  const userToken = await Token.findOne({
    passwordResetToken: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    return sendResponse(res, "error", "Token is invalid or has expired.", 404);
  }

  const user = await User.findOne({ _id: userToken.userId });
  if (!user) return sendResponse(res, "error", "User not found.", 404);

  user.password = password;
  await user.save();

  sendResponse(
    res,
    "message",
    "Password successfully reset. Please login.",
    200
  );
});

const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword)
    return sendResponse(res, "error", "Missing parameters.", 400);
  const user = await User.findById(req.user._id);
  if (!user) return sendResponse(res, "error", "User not found.", 404);

  const passwordIsCorrect = await bcrypt.compare(
    currentPassword,
    user.password
  );
  if (!passwordIsCorrect)
    return sendResponse(
      res,
      "error",
      "Incorrect password. Please try again.",
      401
    );

  if (user && passwordIsCorrect) {
    user.password = newPassword;
    await user.save();

    sendResponse(
      res,
      "message",
      "Password changed successfully. Please log in again.",
      200
    );
  } else {
    sendResponse(res, "error", "Something went wrong. Please try again.", 400);
  }
});

module.exports = {
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
};
