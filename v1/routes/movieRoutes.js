const express = require("express");
const { checkUserId } = require("../../auth/token_validation");
const apicache = require("apicache");
const movieController = require("../../controllers/movieController");

const router = express.Router();
// Added cache in just for fun.
const cache = apicache.middleware;

//NOTE: By using the 'checkUserId' function as middleware, it checks whether a user is logged in and adds the userId to to req.userId if they are
// This can be used to determine whether to return presale movies with the response

// Returns:
// {"success":true,"data":[{"movie_id":"M_001","movie_name":"Citizen Kane","isPresale":0},{"movie_id":"M_002","movie_name":"Titanic","isPresale":0},{"movie_id":"M_003","movie_name":"Demon Slayer","isPresale":0},{"movie_id":"M_004","movie_name":"The Good, The Bad, And The Ugly","isPresale":0},{"movie_id":"M_005","movie_name":"Citizen Kane 2","isPresale":1}]}
router.get("/", checkUserId, movieController.getAllMovies);

// Returns:
// {"success":true,"data":{"movie_id":"M_002","movie_name":"Titanic","isPresale":0,"showings":[{"showing_id":"ST_002","theatre_id":"T_002","movie_id":"M_002","show_time":"2022-11-26T18:00:00.000Z","movie_name":"Titanic","isPresale":0,"theatre_name":"Cineplex SW"},{"showing_id":"ST_003","theatre_id":"T_003","movie_id":"M_002","show_time":"2022-11-26T20:00:00.000Z","movie_name":"Titanic","isPresale":0,"theatre_name":"Landmark NE"}]}}
router.get("/:movie_id", checkUserId, movieController.getOneMovie);

module.exports = router;
