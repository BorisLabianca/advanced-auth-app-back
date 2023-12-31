// Imports
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const connectDB = require("./database");
const { handleNotFound } = require("./utils/helper");
const { errorHandler } = require("./middlewares/error");
require("dotenv").config();

// Route imports
const userRoutes = require("./routes/user");

const app = express();

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
