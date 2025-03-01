const mongoose = require("mongoose");

const eventSchema = mongoose.Schema({
  action: {
    type: String,
    trim: true,
    required: true,
  },
  author: {
    type: String,
    trim: true,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now(),
  },
  resource: {
    type: String,
    trim: true,
    required: true,
  },
});

const eventModel = mongoose.model("event", eventSchema);

module.exports = eventModel;
