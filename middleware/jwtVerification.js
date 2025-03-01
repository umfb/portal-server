const jwt = require("jsonwebtoken");
const userModel = require("../models/users.model");

async function verifyToken(req, res, next) {
  try {
    if (!req.headers) {
      return res.status(401).json({ message: "Missing header", status: false });
    }
    const token = req.headers.authorization.split(" ")[1];
    if (!token) {
      return res
        .status(401)
        .json({ message: "No token found in auth header", status: false });
    }
    console.log(token);
    jwt.verify(token, process.env.JWT_SECRET_KEY, async (error, user) => {
      if (error) {
        return res
          .status(401)
          .json({ message: "Error verifying token", status: false, error });
      }
      if (user) {
        const loggedInUser = await userModel.findOne({
          email: user.sub,
        });
        if (!loggedInUser)
          return res
            .status(403)
            .json({ message: "User does not exist in DB", status: false });
        req.user = loggedInUser;
        next();
      }
    });
  } catch (error) {
    console.log("error:", error);

    return res.sendStatus(403);
  }
}

module.exports = verifyToken;
