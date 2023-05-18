const DatabaseConnection = require("../config/database");
const connection = DatabaseConnection.getInstance(); // get Singleton instance

const modelMethods = {};

modelMethods.getAllShowings = (isRegisteredUser, query) => {
  return new Promise(async (resolve, reject) => {
    try {
      const movie_id = query.movie_id || "%";
      const theatre_id = query.theatre_id || "%";
      const results = await connection.query(
        `SELECT * FROM SHOWING S INNER JOIN MOVIE M ON M.movie_id = S.movie_id INNER JOIN THEATRE T ON T.theatre_id = S.theatre_id 
      WHERE (M.isPresale = false OR ?) AND M.movie_id LIKE ? AND T.theatre_id LIKE ?`,
        [isRegisteredUser, movie_id, theatre_id]
      );
      return resolve(results);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.getOneShowing = (showing_id, isRegisteredUser) => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `SELECT * FROM SHOWING S INNER JOIN MOVIE M ON M.movie_id = S.movie_id INNER JOIN THEATRE T ON T.theatre_id = S.theatre_id 
      WHERE S.showing_id = ? AND (M.isPresale = false OR ?)`,
        [showing_id, isRegisteredUser]
      );
      return resolve(results[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

module.exports = modelMethods;
