const express = require("express");
const emailController = require("../../controllers/emailController");

const router = express.Router();

router.get("/welcome", emailController.sendWelcomeNews);
router.get("/news", emailController.sendMovieNewsAllUsers);
router.get("/:ticket_id", emailController.sendTicketReceipt);

module.exports = router;
