const mongoose = require("mongoose");

const connection = async (url) => {
  try {
    const connected = mongoose.connect(url, {
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
    });
    if (connected) return console.log("connection to mongodb established");
    else {
      console.log("couldn't connect to mongodb");
    }
  } catch (error) {
    console.log(error);
  }
};

module.exports = connection;
