const refundService = require("../services/refundService");

const controllerMethods = {};

controllerMethods.getCreditByTicket = async (req, res) => {
  try {
    const { ticket_id } = req.params;
    let results = await refundService.getCreditByTicket(ticket_id);
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "no credit available" });
    }
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
};

controllerMethods.getTotalCreditByUser = async (req, res) => {
  try {
    const user_id = req.userId;
    const isRegisteredUser = user_id != null;
    if (!isRegisteredUser)
      res.status(404).json({ success: false, message: "user id not found" });
    else {
      let credits = await refundService.getCreditByUser(user_id);
      let total_credit = 0;
      if (credits.length > 0) {
        credits.forEach((credit) => {
          total_credit += credit.credit_available;
        });
        res.json({ success: true, data: total_credit });
      } else {
        res.json({ success: true, data: total_credit });
      }
    }
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
};

module.exports = controllerMethods;
