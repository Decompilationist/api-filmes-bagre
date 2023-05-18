const refundModel = require("../models/Refund");

const serviceMethods = {};

// returns credit object if it exists else returns [];
// requires a ticket_id
serviceMethods.getCreditByTicket = async (ticket_id) => {
  const result = await refundModel.getCreditByTicket(ticket_id);
  return result;
};

// returns all credit objects specific to a user
// else returns []
// requires a user_id
serviceMethods.getCreditByUser = async (user_id) => {
  const result = await refundModel.getCreditByUser(user_id);
  return result; 
};

// returns nothing
// updates credit within the credit table. requires format in a credit obj with ticket_id and credit_available keys
serviceMethods.updateCredit = async (p_id, credit_obj) => {
  try {
    credit_obj.forEach(async (credit_item) => {
      const { ticket_id, refund } = credit_item;
      if (refund) await refundModel.useCreditAsRefund(p_id, refund, ticket_id);
        await refundModel.updateCredit(credit_item);
      });
    return null;
  } catch (error) {
    return (error)
  }  
    
};

serviceMethods.makeNewRefund = async (ticket_id, credit, expiration_date) => {
  try {
    const result = await refundModel.makeNewRefund(ticket_id, credit, expiration_date);
    return result;
  } catch (err) {
    return (err);
  }
}

module.exports = serviceMethods;
