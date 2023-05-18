const DatabaseConnection = require("../config/database");
const connection = DatabaseConnection.getInstance();
const { v4: uuid } = require("uuid");

const modelMethods = {};

// Return all tickets.
modelMethods.getAllTickets = (query) => {
  return new Promise(async (resolve, reject) => {
    const user_id = query.user_id || "%";
    try {
      const results = await connection.query(
        `SELECT * FROM TICKET WHERE (user_id LIKE ? OR ?)`,
        [user_id, user_id === "%"]
      );
      return resolve(results);
    } catch (err) {
      return reject(err);
    }
  });
};

// Return all tickets with detailed information.
modelMethods.getAllTicketsDetailed = (query) => {
  return new Promise(async (resolve, reject) => {
    const user_id = query.user_id || "%";
    try {
      const results = await connection.query(
        `SELECT * 
          FROM SHOWING SH Inner join SEATS S ON SH.showing_id = S.showing_id 
          INNER JOIN TICKET T ON S.seat_id = T.seat_id INNER JOIN MOVIE M ON SH.movie_id = M.movie_id 
          INNER JOIN THEATRE TH ON TH.theatre_id = SH.theatre_id 
          WHERE (user_id LIKE ? OR ?)`,
        [user_id, user_id === "%"]
      );
      return resolve(results);
    } catch (err) {
      return reject(err);
    }
  });
};

// Get Tickets by ID only.
// RETURNS {user_id:"", seat_id:"", cost: "", show_time: ""}
modelMethods.getTicketById = (ticket_id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `SELECT user_id, S.seat_id, S.cost, show_time from SHOWING SH Inner join SEATS S ON SH.showing_id = S.showing_id 
              INNER JOIN TICKET T ON S.seat_id = T.seat_id Where T.ticket_id = ?`,
        [ticket_id]
      );
      return resolve(results[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

// Create Ticket.
// REQUIRES: User_id, and the body to contain key for "seat_id" and "cost"
// RETURNS {user_id:"", seat_id:"", cost: "", isCredit: ""}
modelMethods.createTicket = (body, user_id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const { seat_id, payment_id } = body;
      const ticket_id = uuid();
      const insert = await connection.query(
        `INSERT INTO TICKET(ticket_id, user_id, seat_id, payment_id) VALUES (?, ?, ?, ?)`,
        [ticket_id, user_id, seat_id, payment_id]
      );
      const results = await connection.query(
        `SELECT * FROM TICKET WHERE ticket_id = ?`,
        [ticket_id]
      );
      return resolve(results[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

// TODO: Do we need to check if seat is available? or do we do this during payment? ask Graeme
// TODO: I think the  route should be POST /tickets/:ticket_id, body should be "cancel":true
// Cancel Ticket - Regardless of user type or date. Controller must do logic to
// determine additional details.
// REQUIRES: ticket_id, seat_id, and credit
// RETURNS {ticket_id:"", credit_available: ""}
modelMethods.cancelTicketById = (ticket_id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const update = await connection.query(
        `UPDATE TICKET SET is_credited = true WHERE ticket_id = ?`,
        [ticket_id]
      );
      return resolve(update);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.getOneTicket = (ticket_id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `SELECT * 
          FROM SHOWING SH Inner join SEATS S ON SH.showing_id = S.showing_id 
          INNER JOIN TICKET T ON S.seat_id = T.seat_id INNER JOIN MOVIE M ON SH.movie_id = M.movie_id 
          INNER JOIN THEATRE TH ON TH.theatre_id = SH.theatre_id 
          WHERE T.ticket_id = ?`,
        [ticket_id]
      );
      return resolve(results[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

module.exports = modelMethods;
