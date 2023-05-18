const DatabaseConnection = require("../config/database");
const connection = DatabaseConnection.getInstance(); // get Singleton instance

const modelMethods = {};

modelMethods.getAllSeats = (isRegisteredUser, query) => {
  return new Promise(async (resolve, reject) => {
    try {
      const showing_id = query.showing_id || "%";
      const results = await connection.query(
        `SELECT ST.* FROM SEATS ST INNER JOIN SHOWING SH ON SH.showing_id = ST.showing_id 
      INNER JOIN MOVIE M ON SH.movie_id = M.movie_id 
      WHERE (M.isPresale = false OR ?) AND SH.showing_id LIKE ?`,
        [isRegisteredUser, showing_id]
      );
      return resolve(results);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.getOneSeat = (seat_id, isRegisteredUser) => {
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `SELECT ST.* FROM SEATS ST INNER JOIN SHOWING SH ON SH.showing_id = ST.showing_id 
      INNER JOIN MOVIE M ON SH.movie_id = M.movie_id 
      WHERE ST.seat_id = ? AND (M.isPresale = false OR ?)`,
        [seat_id, isRegisteredUser]
      );
      return resolve(results[0]);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.getPresaleSeatsForOneShowing = (showing_id) => {
  // function to determine if a showing is presale restricted (10% sold in presale)
  return new Promise(async (resolve, reject) => {
    try {
      const results = await connection.query(
        `SELECT M.isPresale, ST.booked FROM SEATS ST INNER JOIN SHOWING SH ON SH.showing_id = ST.showing_id
       INNER JOIN MOVIE M ON M.movie_id = SH.movie_id
       WHERE SH.showing_id = ?`,
        [showing_id]
      );
      return resolve(results);
    } catch (err) {
      return reject(err);
    }
  });
};

modelMethods.updateOneSeat = (seat_id, isBooked) => {
  return new Promise((resolve, reject) => {
    try {
      const update = connection.query(`UPDATE SEATS SET booked = ? WHERE seat_id = ?`,
            [isBooked, seat_id]
      );
      return resolve(update);
    } catch (err) {
      return reject(err);
    }
  });
}

module.exports = modelMethods;
