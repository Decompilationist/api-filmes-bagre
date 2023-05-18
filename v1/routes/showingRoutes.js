const express = require("express");
const { checkUserId } = require("../../auth/token_validation");
const showingController = require("../../controllers/showingController");

const router = express.Router();

// {"success":true,"data":[{"showing_id":"ST_001","theatre_id":"T_001","movie_id":"M_001","show_time":"2022-11-26T16:00:00.000Z","movie_name":"Citizen Kane","isPresale":0,"theatre_name":"MovieTown NE"},{"showing_id":"ST_002","theatre_id":"T_002","movie_id":"M_002","show_time":"2022-11-26T18:00:00.000Z","movie_name":"Titanic","isPresale":0,"theatre_name":"Cineplex SW"},{"showing_id":"ST_003","theatre_id":"T_003","movie_id":"M_002","show_time":"2022-11-26T20:00:00.000Z","movie_name":"Titanic","isPresale":0,"theatre_name":"Landmark NE"},{"showing_id":"ST_004","theatre_id":"T_003","movie_id":"M_003","show_time":"2022-11-26T16:00:00.000Z","movie_name":"Demon Slayer","isPresale":0,"theatre_name":"Landmark NE"},{"showing_id":"ST_005","theatre_id":"T_002","movie_id":"M_004","show_time":"2022-12-10T16:00:00.000Z","movie_name":"The Good, The Bad, And The Ugly","isPresale":0,"theatre_name":"Cineplex SW"},{"showing_id":"ST_006","theatre_id":"T_001","movie_id":"M_005","show_time":"2022-12-13T16:00:00.000Z","movie_name":"Citizen Kane 2","isPresale":1,"theatre_name":"MovieTown NE"}]}
router.get("/", checkUserId, showingController.getAllShowings);

// TODO: return the movie, theatre name, and all seats associated with it once SEAT has been implemented
router.get("/:showing_id", checkUserId, showingController.getOneShowing);

module.exports = router;
