const userModel = require("../models/users.model");
const tokenModel = require("../models/refreshTokens.model");
const eventModel = require("../models/events.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mailer = require("nodemailer");
const crypto = require("crypto");
require("dotenv").config();
const { google } = require("googleapis");
const deptModel = require("../models/depts.model");
const REDIRECT_URI = "https://developers.google.com/oauthplayground";
const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  REDIRECT_URI
);

oAuth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

const allowedKeys = [
  "firstname",
  "lastname",
  "email",
  "password",
  "accessRole",
  "phoneNumber",
  "department",
];

const register = async (req, res, next) => {
  try {
    const {
      firstname,
      lastname,
      email,
      password,
      accessRole,
      phoneNumber,
      department,
    } = req.body;
    if (
      !email ||
      !password ||
      !firstname ||
      !lastname ||
      !accessRole ||
      !phoneNumber ||
      !department
    ) {
      return res
        .status(404)
        .json({ message: "Missing credential", status: false });
    }
    try {
      const existingUser = await userModel.findOne({ email });
      if (existingUser) {
        return res.status(403).json({ message: "User already exists" });
      }
      const extraKeys = Object.keys(req.body).filter(
        (key) => !allowedKeys.includes(key)
      );
      if (extraKeys.length > 0) {
        console.log(extraKeys);
        return res
          .status(403)
          .json({ message: "Invalid schema", status: false });
      }
      const newUser = await userModel.create(req.body);
      if (!newUser)
        return res.status(401).json({
          message: "An error occured while creating new user",
          status: false,
        });
      const existingDepartment = await deptModel.findOne({
        deptName: department,
      });
      if (!existingDepartment) {
        const addedDepartment = await deptModel.create({
          deptName: department,
          members: [{ email }],
        });

        if (!addedDepartment) {
          console.log("error adding new dept.");
          return res.sendStatus(401);
        }
      } else {
        const emailExists = existingDepartment.members.some(
          (member) => member === email
        );
        if (!emailExists) existingDepartment.members.push({ email });
        await existingDepartment.save();
      }
      const mailMessage = `<p>Hey, <br/> ${firstname} ${lastname}</p>
<p>Your profile has been created successfully, your default password is ${password}</p>

<p>Login <a href="https://portal-kappa-liard.vercel.app">here</></p>`;

      const mailSubject = "Profile Created";
      const sentMail = await sendEmail(email, mailMessage, mailSubject);
      if (!sentMail) {
        return res
          .status(401)
          .json({ message: "Error sending mail", status: false });
      }
      const authHeader = req.headers.authorization;
      const accessToken = authHeader.split(" ")[1];
      jwt.verify(
        accessToken,
        process.env.JWT_SECRET_KEY,
        async (error, user) => {
          if (error) {
            return res
              .status(401)
              .json({ message: "Error verifying user", status: false });
          }
          if (user) {
            const author = await userModel.findOne({ email: user.sub });
            if (!author) {
              return res
                .status(401)
                .json({ message: "User not found", status: false });
            }
            const eventObj = {
              author: author.email,
              action: "Created new profile",
              resource: "Create Profile",
            };
            const recordedEvent = await eventModel.create(eventObj);
            if (!recordedEvent) {
              return res
                .status(500)
                .json({ message: "Event not recorded", status: false });
            }
          }
          return res.status(200).json({
            message: "User profile successfully created",
            status: true,
          });
        }
      );
    } catch (error) {
      console.log(error);
      if (error.name === "ValidationError") {
        return res.status(401).json({ message: error.message, status: false });
      }
      return res.sendStatus(500);
    }
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
};

const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(401)
        .json({ message: "Missing credentials", status: false });
    }
    const user = await userModel.findOne({ email });
    if (!user) {
      return res
        .status(401)
        .json({ message: "User does not exist", status: false });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log(passwordMatch);
    if (!passwordMatch) {
      return res
        .status(403)
        .json({ message: "Incorrect email or password", status: false });
    }
    const payload = {
      sub: user.email,
      role: "user",
    };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET_KEY, {
      expiresIn: "10m",
    });
    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
      expiresIn: "21d",
    });
    const savedRefreshToken = await tokenModel.create({
      userId: user._id,
      refreshToken,
    });
    if (!savedRefreshToken)
      return res
        .status(401)
        .json({ message: "Error saving refresh token to DB" });
    if (!accessToken || !refreshToken) {
      return res
        .status(401)
        .json({ message: "Error occured while generating token" });
    }
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.PRODUCTION === true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    const eventObj = {
      author: email,
      resource: "Authentication",
      action: "Logged in",
    };
    const recordedEvent = await eventModel.create(eventObj);
    if (!recordedEvent) {
      return res
        .status(401)
        .json({ message: "Event not recorded", status: false });
    }
    return res.status(200).json({
      message: "Login successful",
      status: true,
      accessToken,
      name: user.firstname + " " + user.lastname,
      email: user.email,
    });
  } catch (error) {
    console.log(error);
    return res.sendStatus(500);
  }
};

const refreshToken = async (req, res) => {
  try {
    const token = req.cookies.refreshToken;
    if (!token) {
      return res
        .status(401)
        .json({ message: "Token not found in cookie", status: false });
    }

    let verifiedToken;
    try {
      verifiedToken = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch (error) {
      return res
        .status(403)
        .json({ message: "Invalid refresh token", status: false });
    }

    const storedToken = await tokenModel.findOne({ refreshToken: token });
    if (!storedToken) {
      return res
        .status(401)
        .json({ message: "Stored refresh token not found", status: false });
    }

    const payload = { sub: verifiedToken.sub, role: "user" };
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET_KEY, {
      expiresIn: "10m",
    });

    console.log("Access token refreshed");
    return res.json({ accessToken });
  } catch (error) {
    console.error("Error refreshing token:", error);
    return res
      .status(500)
      .json({ message: "Internal Server Error", status: false });
  }
};

const verifyUser = async (req, res, next) => {
  const user = req.user;
  console.log("user:", user);
  if (!user)
    return res
      .status(401)
      .json({ message: "Unable to verify user", status: false });
  return res
    .status(200)
    .json({ message: "User still valid", status: true, user });
};

async function createTransporter() {
  try {
    const accessToken = await oAuth2Client.getAccessToken();
    if (!accessToken) {
      console.error("Access token not available");
      return;
    }

    const transporter = mailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: "unilagmfbankltd1@gmail.com",
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        refreshToken: process.env.REFRESH_TOKEN,
        accessToken: accessToken.token,
      },
    });
    return transporter;
  } catch (error) {
    console.error("Error creating transporter:", error);
    throw error;
  }
}

async function sendEmail(recipient, message, subject) {
  try {
    const transporter = await createTransporter();
    const mailOptions = {
      from: "unilagmfbankltd1@gmail.com",
      to: recipient,
      subject,
      html: message,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent successfully");
    if (!info) {
      return false;
    }
    return true;
  } catch (error) {
    console.error("Error sending email:", error);
    return false;
  }
}

const forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;
    console.log(email);
    const user = await userModel.findOne({ email });
    if (!user) return res.status(401).json({ message: "No user found" });
    const resetToken = user.generateResetPasswordToken();
    await user.save();
    const resetUrl = `http://localhost:5173/reset-password?token=${resetToken}`;

    if (!email) {
      return res
        .status(401)
        .json({ message: "Email is missing", status: false });
    }
    const mailMessage = `Hello ${user.firstname},
<p>We received a request to reset your password. If you made this request, please click the link below to reset your password:

${resetUrl}</p>

<p>This link will expire in 30 minutes for security reasons. If you did not request a password reset, please ignore this email or contact support.</p>

<p>Best regards, <br/>
Unilag Microfinance Bank Support Team</p>`;
    const mailSubject = "Reset Password - Action Required!!!";
    const sentMail = await sendEmail(email, mailMessage, mailSubject);
    if (!sentMail) {
      return res
        .status(500)
        .json({ message: "Error sending mail", status: false });
    }
    return res
      .status(200)
      .json({ message: "A reset email has been sent", status: true, sentMail });
  } catch (error) {
    return res.sendStatus(500);
  }
};

const resetPassword = async (req, res, next) => {
  const { token } = req.query;
  if (!token) {
    return res.status(401).json({ message: "Incorrect url" });
  }
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const user = await userModel.findOne({ resetPasswordToken: hashedToken });
  console.log("from reset:", user);

  if (!user || user.resetPasswordTokenExpiryDate < Date.now()) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
  return res
    .status(200)
    .json({ message: "Token verified", status: true, token });
};

const updatePassword = async (req, res, next) => {
  const { token, newPassword } = req.body;

  if (!token) {
    return res.status(404).json({ message: "Incorrect url" });
  }
  console.log(token);
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const user = await userModel.findOne({ resetPasswordToken: hashedToken });
  console.log(user);
  if (!user || user.resetPasswordTokenExpiryDate < Date.now()) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }

  const newUser = await userModel.findOneAndUpdate(
    {
      resetPasswordToken: hashedToken,
      resetPasswordTokenExpiryDate: { $gt: Date.now() },
    },
    {
      $set: {
        password: newPassword,
        resetPasswordToken: null,
        resetPasswordTokenExpiryDate: null,
      },
    },
    { new: true }
  );

  if (!newUser) {
    return res
      .status(403)
      .json({ message: "Invalid or expired token", status: false });
  }

  return res.status(200).json({ message: "Password updated", status: true });
};

const fetchUsers = async (req, res, next) => {
  try {
    const users = await userModel.find({});
    if (!users) {
      return res.status(404).json({ message: "no user found", status: false });
    }
    return res
      .status(200)
      .json({ message: "users found", users, status: true });
  } catch (error) {
    return res.sendStatus(500);
  }
};

const logOut = async (req, res) => {
  if (req.cookies) {
    const token = req.cookies.refreshToken;
    await tokenModel.deleteOne({ refreshToken: token });
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });
    res.status(200).json({ message: "Logged out successfully" });
  } else {
    console.log("failed");
    return res
      .status(403)
      .json({ message: "Cookies not found", status: false });
  }
};
module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword,
  updatePassword,
  fetchUsers,
  verifyUser,
  refreshToken,
  logOut,
};
