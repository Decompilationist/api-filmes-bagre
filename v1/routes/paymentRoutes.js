const express = require("express");
const { checkUserId } = require("../../auth/token_validation");
const paymentController = require("../../controllers/paymentController");
const regUserPaymentService = require("../../services/regUserPaymentService");
const userPaymentService = require("../../services/userPaymentService");


const router = express.Router();

// Instantiate the paymentController object and the 
// two strategy objects
const myWayToPay = new paymentController();
const registeredUser = new regUserPaymentService();
const normalUser = new userPaymentService();



// Set the payment Strategy member in the payment Controller
// based on whether it is a registered user or not.
const assignPaymentType = (req, res, next) => {
    const user_id = req.userId;
    if(user_id) myWayToPay.setPaymentStrategy(registeredUser);
    else myWayToPay.setPaymentStrategy(normalUser);    
    next();
}

// REQUIRES: {
//
//            "seat_id": "S_121022_9_002_004_22",
//            "credit_card":"1234", - THIS CAN BE EMPTY IF PAYING WITH ALL CREDIT OR IS A REGISTERED USER
//            "ticket_id": "TK_0014", - THIS CAN BE EMPTY IF PAYING WITH ALL CREDIT CARD OR IS A REGISTERED USER
//            "use_credit": true -- TRUE - USER REFUND, FALSE, DO NOT USE REFUND
// 
// }
// RETURNS: { "success": true, "data": {
//            "payment_id": "23830870-1cea-4ca8-9627-69c6f519c3c0",
//            "total_amount": 10,
//            "completion_date": "2022-11-30T06:16:03.000Z"
//            }
// }
router.put('/', checkUserId, assignPaymentType, myWayToPay.pay);

router.patch('/:user_id', checkUserId, assignPaymentType, myWayToPay.payMembership);

module.exports = router;