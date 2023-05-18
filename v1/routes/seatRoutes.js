const express = require("express");
const { checkUserId } = require("../../auth/token_validation");
const apicache = require("apicache");
const seatController = require("../../controllers/seatController");

const router = express.Router();
// Added cache in just for fun.
const cache = apicache.middleware;

// Returns:
router.get("/", checkUserId, seatController.getAllSeats);

// Returns:
router.get("/:seat_id", checkUserId, seatController.getOneSeat);

module.exports = router;
