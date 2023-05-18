const emailService = require("../services/emailService");

const controllerMethods = {};

controllerMethods.sendTicketReceipt = async (req, res) => {
  try {
    const { ticket_id } = req.params;
    const email = "graemefolk@gmail.com";
    let results = await emailService.sendTicketReceipt(ticket_id, email);
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "No ticket found." });
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.sendWelcomeNews = async (req, res) => {
  try {
    console.log("send movie news");
    let results = await emailService.sendWelcomeEmail(
      "graemefolk@gmail.com",
      "Graeme"
    );
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "No user found." });
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.sendMovieNewsAllUsers = async (req, res) => {
  try {
    console.log("send movie new all users");
    let results = await emailService.sendMovieNewsAllUsers();
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "No users found." });
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

module.exports = controllerMethods;
