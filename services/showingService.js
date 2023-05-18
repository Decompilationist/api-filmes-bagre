const showingModel = require("../models/Showing");
const { getAllSeats } = require("./seatService");

const serviceMethods = {};

serviceMethods.getAllShowings = async (isRegisteredUser, query) => {
  const results = await showingModel.getAllShowings(isRegisteredUser, query);
  return results;
};

serviceMethods.getOneShowing = async (showing_id, isRegisteredUser) => {
  const results = await showingModel.getOneShowing(
    showing_id,
    isRegisteredUser
  );
  if (results) {
    // add a list of all seats for the chosen showing
    const query = {};
    query.showing_id = showing_id;
    let seats = await getAllSeats(isRegisteredUser, query);
    results.seats = seats;
  }
  return results;
};

module.exports = serviceMethods;
