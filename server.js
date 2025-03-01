const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const userRoute = require("./routers/users.router");
const roleRoute = require("./routers/role.router");
const eventRoute = require("./routers/events.router");
const pingRoute = require("./routers/ping.router");
const MONGODB_CONNECTION = require("./connection/mongodb.connection");
require("dotenv").config();
const app = express();

const allowedOrigins = [
  "http://localhost:5173",
  "https://portal-kappa-liard.vercel.app",
  "http://localhost:5000",
];

app.use(cookieParser());
app.use(express.json({}));
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        console.log(origin);

        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use("/", userRoute);
app.use("/role", roleRoute);
app.use("/events", eventRoute);
app.use("/ping", pingRoute);

MONGODB_CONNECTION(process.env.MONGODB_URL);
const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log("server is running on port", port);
});
