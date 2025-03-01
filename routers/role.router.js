const express = require("express");
const router = express.Router();

const {
  addRole,
  getRoles,
  editRole,
  deleteRole,
} = require("../controllers/role.controller");
const verifyToken = require("../middleware/jwtVerification");

router.post("/add-role", verifyToken, addRole);
router.post("/get-roles", verifyToken, getRoles);
router.post("/edit-role/:role", editRole);
router.post("/delete-role/:role", deleteRole);

module.exports = router;
