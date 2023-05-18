const userModel = require("../models/User");
const { sendWelcomeEmail } = require("./emailService");
const { v4: uuid } = require("uuid");

const serviceMethods = {};

serviceMethods.getAllUsers = async () => {
  const results = await userModel.getAllUsers();
  return results;
};

serviceMethods.getOneUser = async (id) => {
  const results = await userModel.getOneUser(id);
  return results;
};

serviceMethods.createUser = async (body) => {
  const id = uuid();
  const result = await userModel.createUser(body, id);
  if (result) {
    const results = await userModel.getOneUser(id);
    sendWelcomeEmail(results.email_address, results.first_name);
    return results;
  }
  return null;
};

serviceMethods.updateUser = async (body, id) => {
  const result = await userModel.updateUser(body, id);
  if (result) {
    const results = await userModel.getOneUser(id);
    return results;
  }
  return null;
};

serviceMethods.deleteUser = async (id) => {
  const results = await userModel.deleteUser(id);
  return results;
};

serviceMethods.getUserByEmail = async (body) => {
  const { email_address } = body;
  const results = await userModel.getUserByEmail(email_address);
  return results;
};

serviceMethods.updateRenewalDate = async (renewal_date, id) => {
  const results = await userModel.updateRenewalDate(renewal_date, id);
  return results;
};

module.exports = serviceMethods;
