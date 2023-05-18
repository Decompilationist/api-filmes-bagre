const express = require("express");
const { checkToken } = require("../../auth/token_validation");
const userController = require("../../controllers/userController");

const router = express.Router();

// NOTE: The JWT token is returned in the JSON body when a user logs in.
// In order to access any of the APIs behind the 'checkToken' method, the
// user needs to include that token in the header of the request {headers: { Authorization: `JWT ${jwt}` },}

//NOTE: By using the 'checkToken' function as middleware, it checks whether a user is logged in adds the userId to to req.userId if they are
// If the user is not logged in, it will deny them access to use that endpoint.

router.get("/", userController.getAllUsers); // in theory this should probably be an admin function, but leaving it open for now
router.get("/:userId", checkToken, userController.getOneUser);
router.get("/:userId/tickets", checkToken, userController.getUserTickets);
router.get("/:userId/refunds", checkToken, userController.getUserRefunds);

// Expects:
// { "first_name": "Joe", "last_name": "Blow", "email_address": "joeblowk@test.com", "password": "test", "address": "111 street","credit_card": "123456789"}
// Returns:
// {"success":true,"data":{"id":"fe3bd39b-ae53-4fd4-9e33-dc79fe2bfcb9","first_name":"Joe","last_name":"Blow","email_address":"joeblowk@test.com","password":"$2b$10$y.z7Qv8Zo4g9YdwFqX9juuXM4paV6WdtDWSfBtQIIbFOfOT1kwktq","address":"111 street","credit_card":"123456789","annual_fee_expiry_date":null}}
router.post("/", userController.createUser);

// Expects:
// { "first_name": "Joe", "last_name": "Blow", "email_address": "joeblowk@test.com", "password": "test", "address": "222 street","credit_card": "123456789"}
// Returns:
// {"success":true,"data":{"id":"ea9d5bfa-4443-49f4-a6eb-f930d512e772","first_name":"Joe","last_name":"Blow","email_address":"joeblowk@test.com","password":"$2b$10$GKXzt/UJFZb4Hh68bBl4X.UcyLlvdtXBxH3eMNSyaxU2isPPAd.Vy","address":"2222 street","credit_card":"123456789","annual_fee_expiry_date":null}}
router.patch("/:userId", checkToken, userController.updateUser);

// Returns:
// {"success": true,"message": "Delete successful."}
router.delete("/:userId", checkToken, userController.deleteUser);

// Expects:
// {"email_address": "rperson@ucalgary.ca","password": "1234"}
// Returns:
// {"success":true,"message":"Login successful.","user_id":"U_0001","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJVXzAwMDEiLCJpYXQiOjE2Njk1ODI2NTR9.haVvegionYEQ0PEXLhSiBJVatrJusLtAj24b2L7ywc8"}
router.post("/login", userController.login);

module.exports = router;
