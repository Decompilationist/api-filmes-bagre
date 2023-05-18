const express = require("express");
const { checkUserId } = require("../../auth/token_validation");
const theatreController = require("../../controllers/theatreController");

const router = express.Router();

//NOTE: By using the 'checkUserId' function as middleware, it checks whether a user is logged in and adds the userId to to req.userId if they are
// This can be used to determine whether to return presale movies with the response

// {"success":true,"data":[{"theatre_id":"T_001","theatre_name":"MovieTown NE"},{"theatre_id":"T_002","theatre_name":"Cineplex SW"},{"theatre_id":"T_003","theatre_name":"Landmark NE"}]}
router.get("/", theatreController.getAllTheatres);

// {"success":true,"data":{"theatre_id":"T_001","theatre_name":"MovieTown NE","showings":[{"showing_id":"ST_001","theatre_id":"T_001","movie_id":"M_001","show_time":"2022-11-26T16:00:00.000Z","movie_name":"Citizen Kane","isPresale":0,"theatre_name":"MovieTown NE"}]}}
router.get("/:theatre_id", checkUserId, theatreController.getOneTheatre);

module.exports = router;
