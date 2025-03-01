const express = require("express");
const router = express.Router();

const verifyToken = require("../middleware/jwtVerification");
const {
  register,
  login,
  forgotPassword,
  resetPassword,
  updatePassword,
  fetchUsers,
  verifyUser,
  refreshToken,
  logOut,
} = require("../controllers/users.controller");

router.post("/register", verifyToken, register);
router.post("/login", login);
router.post("/send-email", forgotPassword);
router.get("/reset-password", resetPassword);
router.post("/reset-password", updatePassword);
router.get("/fetch-users", verifyToken, fetchUsers);
router.post("/verify", verifyToken, verifyUser);
router.post("/refresh", refreshToken);
router.post("/logout", verifyToken, logOut);

module.exports = router;
