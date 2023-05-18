const { createConnection } = require("mysql");
const util = require("util");

class DatabaseConnection {
  // Using the Singleton deisgn pattern
  // There is one instance of DatabaseConnection

  instance;
  connection;

  constructor() {
    this.instance == null;
    this.connection == null;
  }

  static getInstance() {
    if (this.instance == null) {
      this.instance = new DatabaseConnection();
      this.instance.getConnection();
    }
    return this.instance;
  }

  getConnection() {
    if (!this.connection) {
      this.connection = createConnection({
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        user: process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.MYSQL_DB,
      });
    }
    return this.connection;
  }

  // a wrapper function to create promises for queries
  query(sql, args) {
    return util
      .promisify(this.connection.query)
      .call(this.connection, sql, args);
  }
}

module.exports = DatabaseConnection;
