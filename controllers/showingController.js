const showingService = require("../services/showingService");

const controllerMethods = {};

controllerMethods.getAllShowings = async (req, res) => {
  try {
    const { query } = req;
    const isRegisteredUser = req.userId != null;
    let results = await showingService.getAllShowings(isRegisteredUser, query);
    if (results.length > 0) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "No showings found." });
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.getOneShowing = async (req, res) => {
  try {
    const { showing_id } = req.params;
    const isRegisteredUser = req.userId != null;
    let results = await showingService.getOneShowing(
      showing_id,
      isRegisteredUser
    );
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "Showing not found." });
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
