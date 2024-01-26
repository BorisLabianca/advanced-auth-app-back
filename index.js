// Imports
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const connectDB = require("./database");
const { handleNotFound } = require("./utils/helper");
const { errorHandler } = require("./middlewares/error");
const cloudinary = require("cloudinary").v2;
require("dotenv").config();

// Route imports
const userRoutes = require("./routes/user");

const app = express();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(
  cors({
    origin: ["http://localhost:5173", "https://authz-app.vercel.app"],
    credentials: true,
  })
);

app.use("/api/users", userRoutes);

app.all("*", handleNotFound);

app.use(errorHandler);

app.listen(process.env.PORT, () => {
  connectDB();
  console.log(`Server started on PORT ${process.env.PORT}`);
});
