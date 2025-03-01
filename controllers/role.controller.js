const roleModel = require("../models/accessRole.model");
const eventModel = require("../models/events.model");
const jwt = require("jsonwebtoken");

const addRole = async (req, res) => {
  try {
    const { role } = req.body;
    const accessToken = req.headers.authorization.split(" ")[1];
    if (!accessToken) return res.sendStatus(403);
    const verifiedAcessToken = jwt.verify(
      accessToken,
      process.env.JWT_SECRET_KEY
    );
    if (!verifiedAcessToken) {
      console.log("not verified (add-role)");
      return res
        .status(403)
        .json({ message: "Error verifying token", status: false });
    }
    if (!role) {
      return res
        .status(403)
        .json({ message: "Input the role please", status: false });
    }
    console.log(role);
    const existingRole = await roleModel.findOne({ role });
    if (existingRole) {
      return res
        .status(403)
        .json({ message: "Role already exists", status: false });
    }
    const payload = {
      role,
      creator: verifiedAcessToken.sub,
    };
    const newRole = await roleModel.create(payload);
    if (!newRole) {
      return res.status(500).json({
        message: "Could not add role, please try again",
        status: false,
      });
    }
    const newEvent = await eventModel.create({
      action: "Created new role",
      author: verifiedAcessToken.sub,
      resource: "Roles Config",
    });

    if (!newEvent)
      return res
        .status(500)
        .json({ message: "Error recording event", status: false });
    return res.status(200).json({ message: "Role added", status: true });
  } catch (error) {
    if (error.code === 11000) {
      console.error("Duplicate key error: This role already exists.");
      return res.status(409).json({
        message: "Duplicate key error: This role already exists.",
        status: false,
      });
    }
    console.log(error);
    return res
      .status(500)
      .json({ message: "An error occured while adding role", status: false });
  }
};

const deleteRole = async (req, res) => {
  try {
    if (!req.params) {
      return res.status(401).json({ message: "Incorrect url", status: false });
    }
    const { role } = req.params;
    console.log(role);
    const deletedRole = await roleModel.deleteOne({ role });
    if (!deletedRole)
      return res
        .status(500)
        .json({ message: "Error occured while deleting role", status: false });
    return res.status(200).json({ message: "Role deleted", status: true });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Internal server error", status: false, error });
  }
};

const editRole = async (req, res) => {
  try {
    if (!req.params)
      return res.status(401).json({ message: "Incorrect url", status: false });
    const { role } = req.params;
    const { newRole } = req.body;
    if (!newRole)
      return res
        .status(401)
        .json({ message: "Missing new role", status: false });
    const updatedRole = await roleModel.findOneAndUpdate(
      {
        role,
      },
      {
        $set: {
          role: newRole,
        },
      },
      { new: true }
    );

    if (!updatedRole)
      return res
        .status(500)
        .json({ message: "Error occured updating role", status: false });
    return res.status(200).json({ message: "Role updated", status: true });
  } catch (error) {}
};

const getRoles = async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.sendStatus(403);
    console.log(user);

    const roles = await roleModel.find({});
    if (!roles) {
      return res
        .status(404)
        .json({ message: "No roles was found", status: false });
    }
    return res.status(200).json({ roles, status: true });
  } catch (error) {
    return res.sendStatus(500);
  }
};

module.exports = { addRole, getRoles, deleteRole, editRole };
