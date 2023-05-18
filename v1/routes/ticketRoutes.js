const express = require("express");
const { checkUserId } = require("../../auth/token_validation");
const ticketController = require("../../controllers/ticketController");

const router = express.Router();

router.get("/", ticketController.getAllTickets);
router.get("/:ticket_id", ticketController.getOneTicket);
router.post("/", checkUserId, ticketController.createTicket);
router.patch("/", checkUserId, ticketController.cancelTicketById);

module.exports = router;
