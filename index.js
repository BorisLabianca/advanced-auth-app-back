// Imports
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const connectDB = require("./database");
const { handleNotFound } = require("./utils/helper");
require("dotenv").config();

// Route imports

const app = express();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors());

app.all("*", handleNotFound);

app.listen(process.env.PORT, () => {
  connectDB();
  console.log(`Server started on PORT ${process.env.PORT}`);
});
