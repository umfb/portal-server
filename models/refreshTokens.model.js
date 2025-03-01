const mongoose = require("mongoose");

const tokenSchema = mongoose.Schema({
  userId: {
    type: String,
    required: true,
  },
  refreshToken: {
    type: String,
    required: true,
  },
  createsAt: {
    type: Date,
    default: Date.now(),
    expires: "7d",
  },
});

const tokenModel = mongoose.model("refreshToken", tokenSchema);

module.exports = tokenModel;
