const userPaymentInterface = require("./userPaymentInterface");

class regUserPaymentService extends userPaymentInterface{

    constructor() {
        super();
    }

// registered
pay = async ( req ) => {
    try {
      const { seat_id, use_credit } = req.body;
      const user_id = req.userId;
      let { credit_card } = req.body;
      let seat_result = await this.seatService.getOneSeat(seat_id, true); 
      if(!seat_result) throw new Error("Seat not found");
      if (!seat_result.is_available) throw new Error("Selected seat is not available.");
      const { cost } = seat_result;
      let outstanding_charge = cost;
      let credits = [];
      let billed_amount = 0;
      
      if (use_credit) {
        credits = await this.refundService.getCreditByUser(user_id);
        if(credits.length === 0) throw new Error("No Credit Available for User");
        credits.every((credit) => {
          let temp = outstanding_charge - credit.credit_available;
          if(temp < 0) temp = 0;
          let refund = outstanding_charge - temp;
          credit.credit_available = credit.credit_available - refund;
          credit.refund = refund;
          outstanding_charge = temp;
          return outstanding_charge != 0;
        });
      }
      if (outstanding_charge > 0) {
        if (!credit_card && user_id) {
          const user_cc = await this.paymentModel.creditCardByUserId(user_id);
          if(!user_cc) throw new Error("No Credit Card Information Available for User");
          credit_card = user_cc.credit_card;
        }
        const payment_result = await this.paymentModel.makePayment(
          credit_card,
          outstanding_charge
        );
        if (!payment_result.success) throw "Payment Denied";
        ({ billed_amount } = payment_result);
      }
      const payment = await this.paymentModel.storePayment();
      if(!payment) throw new Error("Credit_Payment Storage Issue");
      const { payment_id } = payment;
      if(billed_amount > 0) await this.paymentModel.storeCreditCardPayment( payment_id, billed_amount, credit_card);
      if (credits.length > 0) await this.refundService.updateCredit(payment_id, credits);
      return payment;
    } catch(err) {
        return err;
    }
}

payMembership = async ( req ) => {
  try {
    const { user_id }= req.params;
    const { body } = req;
    const payment = await this.paymentService.payRegistration(body, user_id);
    if(payment.code) throw payment;
    return payment;
  } catch (error) {
      return error
  }
  
}

}

module.exports = regUserPaymentService;
