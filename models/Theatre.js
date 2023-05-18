const DatabaseConnection = require("../config/database");
const connection = DatabaseConnection.getInstance(); // get Singleton instance

const modelMethods = {};

modelMethods.getAllTheatres = () => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(`SELECT * FROM THEATRE`, []);
      return resolve(results);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.getOneTheatre = (theatre_id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `SELECT * FROM THEATRE WHERE theatre_id = ?`,
        [theatre_id]
      );
      return resolve(results[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

module.exports = modelMethods;
