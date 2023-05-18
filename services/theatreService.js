const theatreModel = require("../models/Theatre");
const { getAllShowings } = require("./showingService");

const serviceMethods = {};

serviceMethods.getAllTheatres = async () => {
  const results = await theatreModel.getAllTheatres();
  return results;
};

serviceMethods.getOneTheatre = async (theatre_id, isRegisteredUser) => {
  const results = await theatreModel.getOneTheatre(theatre_id);
  if (results) {
    // add a list of all showings for the chosen theatre
    const query = {};
    query.theatre_id = theatre_id;
    let showings = await getAllShowings(isRegisteredUser, query);
    results.showings = showings;
  }
  return results;
};

module.exports = serviceMethods;
