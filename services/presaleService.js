const seatModel = require("../models/Seat");

const serviceMethods = {};

serviceMethods.isPresaleRestricted = async (showing_id) => {
  // function to determine if a showing is presale restricted (10% sold in presale)
  const results = await seatModel.getPresaleSeatsForOneShowing(showing_id);
  if (results[0].isPresale) {
    const totalSeats = results.length;
    const totalBooked = results.filter((s) => s.booked == 1).length;
    return totalBooked / totalSeats >= 0.1;
  } else {
    return false;
  }
};

module.exports = serviceMethods;
