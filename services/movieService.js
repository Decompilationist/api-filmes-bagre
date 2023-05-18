const movieModel = require("../models/Movie");
const { getAllShowings } = require("./showingService");

const serviceMethods = {};

serviceMethods.getAllMovies = async (isRegisteredUser) => {
  const results = await movieModel.getAllMovies(isRegisteredUser);
  return results;
};

serviceMethods.getOneMovie = async (movie_id, isRegisteredUser) => {
  const results = await movieModel.getOneMovie(movie_id, isRegisteredUser);
  if (results) {
    // add a list of all showings for the chosen movie
    const query = {};
    query.movie_id = movie_id;
    let showings = await getAllShowings(isRegisteredUser, query);
    results.showings = showings;
  }
  return results;
};

module.exports = serviceMethods;
