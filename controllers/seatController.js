const seatService = require("../services/seatService");

const controllerMethods = {};

controllerMethods.getAllSeats = async (req, res) => {
  try {
    const { query } = req;
    const isRegisteredUser = req.userId != null;
    let results = await seatService.getAllSeats(isRegisteredUser, query);
    if (results.length > 0) {
      res.json({ success: true, data: results });
    } else {
      console.log("test");
      res.status(404).json({ success: false, message: "No seats found." });
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.getOneSeat = async (req, res) => {
  try {
    const { seat_id } = req.params;
    const isRegisteredUser = req.userId != null;
    let results = await seatService.getOneSeat(seat_id, isRegisteredUser);
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "Seat not found." });
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
