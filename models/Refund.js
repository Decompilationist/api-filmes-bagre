const DatabaseConnection = require("../config/database");
const connection = DatabaseConnection.getInstance(); 
// const test = connection.getConnection();

const modelMethods = {};

// returns credit object if it exists else returns [];
// requires a ticket_id
modelMethods.getCreditByTicket = (ticket_id) => {
  return new Promise( async (resolve, reject) => {
    try {
        const result = await connection.query(
            `SELECT * FROM REFUND WHERE ticket_id = ? AND credit_available > 0 AND expiration_date > ?`,
            [ticket_id, new Date()]);
        resolve(result[0]);
    } catch (err) {
        return reject(err);
    }
  });
};

// returns all credit objects specific to a user
// else returns []
// requires a user_id
modelMethods.getCreditByUser = (user_id) => {
  return new Promise( async (resolve, reject) => {
    try {
        const result = await connection.query(
            `SELECT r.id, t.ticket_id, credit_available FROM REFUND c inner join TICKET t on c.ticket_id = t.ticket_id
                  inner join REGISTERED_USER r on t.user_id = r.id WHERE r.id = ? AND credit_available > 0 AND expiration_date > ?`,
            [user_id, new Date()]);
        return resolve(result);
    } catch (err) {
        return reject(err);
    }
  });
};

// returns nothing
// updates credit within the credit table. requires format in a credit obj with ticket_id and credit_available keys
modelMethods.updateCredit = (credit_item) => {
  return new Promise( async (resolve, reject) => {
    try {
        const { ticket_id, credit_available } = credit_item;
        const result = await connection.query(
            `UPDATE REFUND SET credit_available = ? WHERE ticket_id = ?`,
            [credit_available, ticket_id]);
        return resolve(result);
    } catch (err) {
        return reject(err);
    } 
  });
};

// return the new refund object
// should add the credit to refund.
modelMethods.useCreditAsRefund = (p_id, refund_amount, ticket_id) => {
  return new Promise( async (resolve, reject) => {
    try {
        const insert = await connection.query(
            `INSERT INTO REFUND_PAYMENT(payment_id, refund_amount, refund_ticket_id) Values(?, ?, ?)`,
            [p_id, refund_amount, ticket_id]);
        const result = await connection.query(
            `SELECT * FROM REFUND_PAYMENT WHERE payment_id = ?`,
            [p_id]);
        return resolve(result);
    } catch (err) {
        return reject(err);
    }
  });
};

modelMethods.makeNewRefund = (ticket_id, credit, expiration_date) => {
    return new Promise( async (resolve, reject) => {
        try {
            const insert = await connection.query(`INSERT INTO REFUND(ticket_id, credit_available, expiration_date) VALUES (?, ?, ?)`,
            [ticket_id, credit, expiration_date]);
            
            const results = await connection.query(`SELECT * FROM REFUND WHERE Ticket_id = ?`,
            [ticket_id]);
            return resolve(results[0])
        } catch (err) {
            return reject(err);
        }

            
    })
}


module.exports = modelMethods;