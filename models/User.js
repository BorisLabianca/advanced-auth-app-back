const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please add a name."],
    },
    email: {
      type: String,
      required: [true, "Please add an email."],
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please enter a valid email.",
      ],
    },
    password: {
      type: String,
      required: [true, "Please add a password."],
    },
    photo: {
      type: String,
      required: [true, "Please add a photo."],
      default:
        "https://res.cloudinary.com/dbe27rnpk/image/upload/v1703515550/avatar_vmxetj.png",
    },
    phone: {
      type: String,
      default: "",
    },
    bio: {
      type: String,
      default: "",
    },
    role: {
      type: String,
      required: true,
      default: "Subscriber",
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    userAgent: {
      type: Array,
      required: true,
      default: [],
    },
  },
  {
    timestamps: true,
    minimize: false,
  }
);

const User = mongoose.model("User", userSchema);
module.exports = User;
