const express = require("express");
const router = express.Router();

const { fetchEvents } = require("../controllers/events.controller");

router.post("/fetch-events", fetchEvents);

module.exports = router;
