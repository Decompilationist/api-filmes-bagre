const paymentModel = require("../models/Payment");
const { updateRenewalDate, getOneUser } = require("../services/userService");
const constants = require("../config/constants");

const serviceMethods = {};

serviceMethods.getOnePayment = async (payment_id) => {
    try {
        const result = paymentModel.getOnePayment(payment_id);
        return result;    
    } catch (error) {
        return error;
    }  
};

serviceMethods.payRegistration = async ( body, user_id ) => {
    try{   
        const mem_fee = constants.MEM_FEE;
        let billed_amount = 0;
        let { credit_card } = body;
        if (!credit_card) {
            const user_cc = await paymentModel.creditCardByUserId(user_id);
            if(!user_cc) throw "No Credit Card Information Available for User";
            credit_card = user_cc.credit_card;
        }

        const payment_result = await paymentModel.makePayment(
            credit_card,
            mem_fee
        );

        if (!payment_result.success) throw "Payment Denied";
        ({ billed_amount } = payment_result);
        const payment = await paymentModel.storePayment();
        if(!payment) throw "Credit_Payment Storage Issue";
        const { payment_id } = payment;
        const renewal_date = getExpirationDate();
        const cc_result = await paymentModel.storeCreditCardPayment( payment_id, billed_amount, credit_card);
        const user_update = await updateRenewalDate(renewal_date, user_id);
        const user_result = await getOneUser(user_id);
        payment.billed_amount = billed_amount;
        payment.new_expiry_date = user_result.annual_fee_expiry_date;
        return payment;

   } catch (error) {
        return (error);
    }
}

function getExpirationDate() {
    let current_date = new Date();
    let exp_time = current_date.getTime() + constants.EXPIRATION_PERIOD;
    return new Date(exp_time);
}

module.exports = serviceMethods;