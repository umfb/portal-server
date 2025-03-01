const mongoose = require("mongoose");

const roleSchema = mongoose.Schema(
  {
    role: {
      type: String,
      required: true,
      unique: true,
    },
    creator: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

const roleModel = mongoose.model("role", roleSchema);

module.exports = roleModel;
