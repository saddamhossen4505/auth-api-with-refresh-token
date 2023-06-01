const express = require("express");
const dotenv = require("dotenv");
const colors = require("colors");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoDbConnection = require("./config/db");
const corsOptions = require("./config/corsSetup");
const errorHandler = require("./middlewares/errorHandler");
const userRoute = require("./routes/userRoute");
const userLoginRoute = require("./routes/userLoginRoute");

// Init Express.
const app = express();

// Environment Variable.
dotenv.config();
const PORT = process.env.APP_PORT || 4000;

// Middlewares.
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors(corsOptions));
app.use(cookieParser());

// Error Handler.
app.use(errorHandler);

// Routes.
app.use("/api/v1/user", userRoute);
app.use("/api/v1/auth", userLoginRoute);

// Listen server.
app.listen(PORT, () => {
  mongoDbConnection();
  console.log(`Server is running on port ${PORT}`.bgMagenta.black);
});
