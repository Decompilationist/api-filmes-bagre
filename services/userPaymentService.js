const userPaymentInterface = require("./userPaymentInterface");

class userPaymentService extends userPaymentInterface{

    constructor() {
        super();
    }

// non registered
pay = async ( req ) => {
      try{
        console.log(req.body);
        const { seat_id, ticket_id, use_credit, credit_card } = req.body;
        let seat_result = await this.seatService.getOneSeat(seat_id, false);
        if(!seat_result) throw new Error("Seat not found");
        if (!seat_result.is_available) throw new Error("Selected seat is not available.");
        const { cost } = seat_result;
        let outstanding_charge = cost;
        let credit = [];
        let billed_amount = 0;
  
        if (use_credit) {
          const refund_obj = await this.refundService.getCreditByTicket(ticket_id)
          if(!refund_obj) throw new Error("Ticket is not associated with any refunds");
          let temp = outstanding_charge - refund_obj.credit_available;
          if(temp < 0) temp = 0;
          let refund = outstanding_charge - temp;
          refund_obj.credit_available = refund_obj.credit_available - refund;
          refund_obj.refund = refund;
          outstanding_charge = temp;
          credit.push(refund_obj);
        }
        if (outstanding_charge > 0) {
          const payment_result = await this.paymentModel.makePayment(
            credit_card,
            outstanding_charge
          );
          if (!payment_result.success) throw new Error("Payment Denied");
          ({ billed_amount } = payment_result);
        }
        const payment = await this.paymentModel.storePayment();
        if(!payment) throw new Error("Payment Storage Issue");
        const { payment_id } = payment;
        if(billed_amount > 0) await this.paymentModel.storeCreditCardPayment( payment_id, billed_amount, credit_card);
        if (credit.length > 0) await this.refundService.updateCredit(payment_id, credit);
        return payment;
      } catch(err) {
        return err;
      }
  }

  payMembership = async ( req ) => {
    try {
      const { user_id } = req.params;
      const { body } = req;
      const payment = await this.paymentService.payRegistration(body, user_id);
      if(payment.code) throw payment;
      return payment;
    } catch (error) {
        return err
    }
    
  }

}

module.exports = userPaymentService;
