const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = mongoose.Schema({
  firstname: {
    type: String,
    trim: true,
    required: true,
  },
  lastname: {
    type: String,
    trim: true,
    required: true,
  },
  phoneNumber: {
    type: String,
    trim: true,
    required: true,
  },
  email: {
    type: String,
    trim: true,
    required: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Please enter a valid email address"],
  },
  password: {
    type: String,
    trim: true,
    required: true,
  },
  department: {
    type: String,
    trim: true,
    required: true,
  },
  accessRole: {
    type: String,
    trim: true,
    required: true,
  },
  resetPasswordToken: {
    type: String,
    trim: true,
    default: null,
  },
  resetPasswordTokenExpiryDate: {
    type: Date,
    default: null,
  },
});

const saltRound = 10;

userSchema.pre("save", async function (next) {
  try {
    const hashedPassword = await bcrypt.hash(this.password, saltRound);
    if (hashedPassword) {
      this.password = hashedPassword;
    }
    next();
  } catch (error) {
    console.log(error);
    next();
  }
});

userSchema.pre("findOneAndUpdate", async function (next) {
  try {
    const update = this.getUpdate();

    if (update.$set && update.$set.password) {
      update.$set.password = await bcrypt.hash(update.$set.password, saltRound);
    }
    next();
  } catch (error) {
    console.log(error);
    next();
  }
});

userSchema.methods.generateResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");
  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.resetPasswordTokenExpiryDate = Date.now() + 600000;
  return resetToken;
};

const userModel = mongoose.model("user", userSchema);

module.exports = userModel;
