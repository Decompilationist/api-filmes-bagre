const userPaymentInterface = require("../services/userPaymentInterface");

class paymentController {

  paymentService;

  setPaymentStrategy = (userPaymentInterface) => {
      this.paymentService = userPaymentInterface;
  }
    
  pay = async (req, res) => {
    try {
      
      let result = await this.paymentService.pay( req );
      if(result.message) throw result;
      res.json({ success: true, data: result });
    } catch (e) {
      res.json({ success: false, message: e.message });
    }
};

  payMembership = async (req, res) => {
    try {
      let result = await this.paymentService.payMembership( req );
      if(result.code) throw result;
      res.json({ success: true, data: result });
    } catch (e) {
      res.json({ success: false, message: e.message });
    }
  }
  
}

module.exports = paymentController;

