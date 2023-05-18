// const DatabaseConnection = require("../config/database");

class userPaymentInterface {

    // connection;
    refundService;
    seatService;
    paymentService;
    paymentModel;

    constructor() {
        // this.connection = DatabaseConnection.getInstance().getConnection();
        this.refundService = require("./refundService");
        this.seatService = require("./seatService");
        this.paymentService = require("./paymentService");
        this.paymentModel = require("../models/Payment");
    }

    pay  = ( req ) => {}

    payMembership = ( req ) => {} 

}

module.exports = userPaymentInterface;