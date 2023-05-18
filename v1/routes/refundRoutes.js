const express = require("express");
const { checkUserId } = require("../../auth/token_validation");
const refundController = require("../../controllers/refundController");

const router = express.Router();


// RETURNS: { "status": true, "data": {"ticket_id": "TK_0014", "credit_available": 10, "expiration_date": "2023-11-26T16:00:00.000Z"} } 
router.get('/:ticket_id', refundController.getCreditByTicket);

// RETURNS: { "status": true, "data": 20 } Here the value in data represents the credit available for the user. 
router.get('/', checkUserId, refundController.getTotalCreditByUser);

module.exports = router;