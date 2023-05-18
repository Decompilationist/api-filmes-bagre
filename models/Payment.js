const DatabaseConnection = require("../config/database");
const connection = DatabaseConnection.getInstance(); 
const { v4: uuid } = require("uuid");

const modelMethods = {};

// Returns the credit card info for a specific user.
modelMethods.creditCardByUserId = (user_id) => {
  return new Promise( async (resolve, reject) => {
    try {
    const result = await connection.query(`SELECT credit_card FROM REGISTERED_USER WHERE id = ?`,
      [user_id]);
      return resolve(result[0]);
    } catch (err) {
      return reject(err);
    }  
  });
};

// DUMMY METHOD TO SIMULATE PAYMENT,
// RETURNS A DUMMY PAYMENT OBJECT
modelMethods.makePayment = (credit_card, amount) => {
  return new Promise((resolve, reject) => {
    let date = new Date();
    if (!credit_card) {
      return reject({ success: false, message: "no valid cc number" });
    }
    return resolve({
      success: true,
      cc_number: credit_card,
      billed_amount: amount,
      completion_date: date,
    });
  });
};

// Returns the new credit card payment object
// after inserting into database.
modelMethods.storeCreditCardPayment = (id, amount, credit_card) => {
  return new Promise( async (resolve, reject) => {
    try {
      const insert = await connection.query(`INSERT INTO CREDIT_PAYMENT(payment_id, amount, credit_card) VALUES(?, ?, ?)`,
        [id, amount, credit_card]);
      const result = await connection.query(`SELECT * FROM CREDIT_PAYMENT WHERE payment_id = ?`,
        [id]);
      return resolve(result[0]);
    } catch (err) {
      return reject(err);
    }
    
  });
};

modelMethods.storePayment = () => {
  return new Promise( async (resolve, reject) => {
    try {
      const id = uuid();
      const insert = await connection.query(
      `INSERT INTO PAYMENT(payment_id, completion_date) VALUES (?, ?)`,
      [id, new Date()]);
      const result = await connection.query(`SELECT * FROM PAYMENT WHERE payment_id = ?`,
      [id]);
      return resolve(result[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.getOnePayment = (payment_id) => {
  return new Promise( async (resolve, reject) => {
    try {
      const result = await connection.query(
        `SELECT payment_id, SUM(amount) as total_amount from 
        (SELECT payment_id, SUM(amount) as amount from CREDIT_PAYMENT GROUP BY payment_id
        UNION
        SELECT payment_id, SUM(refund_amount) as amount from REFUND_PAYMENT GROUP BY payment_id) amount
        WHERE payment_id = ?;`,
        [payment_id]);
        return resolve(result[0]);
    } catch (err) {
      return reject(err);
    }
    
  });
};

module.exports = modelMethods;