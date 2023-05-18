const seatModel = require("../models/Seat");
const { isPresaleRestricted } = require("./presaleService");

const serviceMethods = {};

serviceMethods.getAllSeats = async (isRegisteredUser, query) => {
  const results = await seatModel.getAllSeats(isRegisteredUser, query);
  for (let i = 0; i < results.length; i++) {
    // Determine if seat is available or not (takes into account 10% presale limit)
    results[i].is_available = !(
      results[i].booked || (await isPresaleRestricted(results[i].showing_id))
    );
    delete results[i].booked;
  }
  return results;
};

serviceMethods.getOneSeat = async (seat_id, isRegisteredUser) => {
  const result = await seatModel.getOneSeat(seat_id, isRegisteredUser);
  if (result) {
    // Determine if seat is available or not (takes into account 10% presale limit)
    result.is_available = !(
      result.booked || (await isPresaleRestricted(result.showing_id))
    );
    delete result.booked;
  }
  return result;
};

serviceMethods.updateOneSeat = async (seat_id, isBooked) => {
  const result = await seatModel.updateOneSeat(seat_id, isBooked);
  return result;
}

module.exports = serviceMethods;
