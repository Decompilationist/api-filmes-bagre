const DatabaseConnection = require("../config/database");
const connection = DatabaseConnection.getInstance(); // get Singleton instance

const modelMethods = {};

modelMethods.getAllUsers = () => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(`SELECT * FROM REGISTERED_USER`);
      return resolve(results);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.getOneUser = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `SELECT * FROM REGISTERED_USER WHERE id = ?`,
        [id]
      );
      return resolve(results[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.createUser = (body, id) => {
  return new Promise(async (resolve, reject) => {
    const {
      first_name,
      last_name,
      email_address,
      password,
      address,
      credit_card,
    } = body;
    try {
      const results = await connection.query(
        `INSERT INTO REGISTERED_USER (id, first_name, last_name, email_address, password, address, credit_card) values (?,?,?,?,?,?,?)`,
        [
          id,
          first_name,
          last_name,
          email_address,
          password,
          address,
          credit_card,
        ]
      );
      if (results.affectedRows === 1) return resolve(results);
      return resolve(null);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.updateUser = (body, id) => {
  return new Promise(async (resolve, reject) => {
    const {
      first_name,
      last_name,
      email_address,
      password,
      address,
      credit_card,
    } = body;
    try {
      const results = await connection.query(
        `UPDATE REGISTERED_USER SET first_name = ?, last_name = ?, email_address = ?, password = ?, address = ?, credit_card = ? WHERE id = ?`,
        [
          first_name,
          last_name,
          email_address,
          password,
          address,
          credit_card,
          id,
        ]
      );
      if (results.affectedRows === 1) return resolve(results);
      return resolve(null);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.deleteUser = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `DELETE FROM REGISTERED_USER WHERE id = ?`,
        [id]
      );
      if (results.affectedRows === 1) return resolve(results);
      return resolve(null);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.getUserByEmail = (email_address) => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `SELECT * FROM REGISTERED_USER WHERE email_address = ? `,
        [email_address]
      );
      return resolve(results[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.updateRenewalDate = (renewal_date, id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const update = await connection.query(
        `UPDATE REGISTERED_USER SET annual_fee_expiry_date = ? WHERE id = ?`,
        [renewal_date, id]);
        return resolve(update);
    } catch (err) {
      return reject(err);

    }
  })
}

module.exports = modelMethods;
