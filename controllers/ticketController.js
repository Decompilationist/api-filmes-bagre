const ticketService = require("../services/ticketService");

const controllerMethods = {};

controllerMethods.getAllTickets = async (req, res) => {
  try {
    const { query } = req;
    let results = await ticketService.getAllTickets(query);
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "no tickets found" });
    }
  } catch (e) {
    res.status(500).json({
      status: false,
      message: e.message,
    });
  }
};

controllerMethods.getOneTicket = async (req, res) => {
  try {
    const { ticket_id } = req.params;
    let results = await ticketService.getOneTicket(ticket_id);
    if (results) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "no tickets found" });
    }
  } catch (e) {
    res.status(500).json({
      status: false,
      message: e.message,
    });
  }
};

// creates a ticket. Currently assuming the body will
// consist of the Seat_ID
controllerMethods.createTicket = async (req, res) => {
  try {
    const { body, userId } = req;

    let results = await ticketService.createTicket(body, userId);
    if (results.message) throw results;
    if (results) {
      res.status(201).json({ success: true, data: results });
    }
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
};

// TODO: CONFIRM: Set up so that the admin fee is not applied if the user logged in is registered OR if the user_id in the database is tied to a registered user.
// this means that a registered user can cancel a ticket without logging in, and someone can recieve the reg user perk if they bought a ticket when they were
// a regular user and have since become registered.

controllerMethods.cancelTicketById = async (req, res) => {
  try {
    const { body } = req;
    const isRegisteredUser = req.userId != null;
    let results = await ticketService.cancelTicketById(body, isRegisteredUser);
    if (results.code === "ER_DUP_ENTRY") throw "ER_DUP_ENTRY";
    res.json({ success: true, data: results });
  } catch (e) {
    if (e === "ER_DUP_ENTRY") {
      res.status(400).json({
        success: false,
        message: "Ticket has already been cancelled.",
      });
    } else {
      res.status(500).json({ success: false, message: e });
    }
  }
};

module.exports = controllerMethods;
