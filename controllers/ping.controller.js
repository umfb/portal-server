const ping = (req, res) => {
  return res.status(200).send("ok");
};

module.exports = ping;
