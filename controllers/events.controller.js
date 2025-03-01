const eventModel = require("../models/events.model");
const jwt = require("jsonwebtoken");
const userModel = require("../models/users.model");

const fetchEvents = async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET_KEY, async (error, user) => {
    if (error) {
      return res
        .status(401)
        .json({ message: "Error verifying token", status: false, error });
    }
    if (user) {
      const events = await eventModel.find().sort({ _id: -1 });
      if (!events)
        return res
          .status(500)
          .json({ message: "Error fetching events", status: false });

      const authorNames = [];

      for (i = 0; i < events.length; i++) {
        const user = await userModel.findOne({ email: events[i].author });
        if (!user) {
          return res
            .status(500)
            .json({ message: "Unable to fetch author", status: false });
        }
        const authorName = user.firstname + " " + user.lastname;
        authorNames.push(authorName);
      }

      for (i = 0; i < authorNames.length; i++) {
        events[i].author = authorNames[i];
      }

      return res.status(200).json({
        message: "Events fetching was a success",
        status: true,
        events,
      });
    }
  });
};

module.exports = { fetchEvents };
