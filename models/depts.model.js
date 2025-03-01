const mongoose = require("mongoose");

const deptSchema = mongoose.Schema({
  deptName: {
    type: String,
    trim: true,
    required: true,
  },
  members: [
    {
      email: {
        type: String,
        trim: true,
      },
    },
  ],
});

const deptModel = mongoose.model("departments", deptSchema);

module.exports = deptModel;
