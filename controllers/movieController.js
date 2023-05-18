const movieService = require("../services/movieService");

const controllerMethods = {};

controllerMethods.getAllMovies = async (req, res) => {
  try {
    const isRegisteredUser = req.userId != null;
    console.log("isreg:" + isRegisteredUser);
    let results = await movieService.getAllMovies(isRegisteredUser);
    if (results.length > 0) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "No movies found." });
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.getOneMovie = async (req, res) => {
  try {
    const { movie_id } = req.params;
    const isRegisteredUser = req.userId != null;
    let results = await movieService.getOneMovie(movie_id, isRegisteredUser);
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "Movie not found." });
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
