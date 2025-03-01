const express = require("express");
const router = express.Router();

const ping = require("../controllers/ping.controller");

router.get("/ping", ping);

module.exports = router;
