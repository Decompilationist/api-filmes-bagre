const userService = require("../services/userService");
const { getAllTicketsDetailed } = require("../services/ticketService");
const { getCreditByUser } = require("../services/refundService");
const { genSaltSync, hashSync, compareSync } = require("bcrypt");
const { sign } = require("jsonwebtoken");

const controllerMethods = {};

controllerMethods.getAllUsers = async (req, res) => {
  try {
    let results = await userService.getAllUsers();
    if (results.length > 0) {
      res.json({ success: true, data: results });
    } else {
      res.status(404).json({ success: false, message: "No users found." });
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.getOneUser = async (req, res) => {
  try {
    const { userId } = req.params;
    if (req.userId !== userId) {
      res.status(401).json({
        success: false,
        message: "Current user is not authorized to get this information.",
      });
    } else {
      let results = await userService.getOneUser(userId);
      if (results) {
        res.json({ success: true, data: results });
      } else {
        res.status(404).json({ success: false, message: "No user found." });
      }
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.getUserTickets = async (req, res) => {
  try {
    const { userId } = req.params;
    if (req.userId !== userId) {
      res.status(401).json({
        success: false,
        message: "Current user is not authorized to get this information.",
      });
    } else {
      const query = {};
      query.user_id = userId;
      let results = await getAllTicketsDetailed(query);
      if (results) {
        res.json({ success: true, data: results });
      } else {
        res.status(404).json({ success: false, message: "No user found." });
      }
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.getUserRefunds = async (req, res) => {
  try {
    const { userId } = req.params;
    const isRegisteredUser = userId != null;
    if (!isRegisteredUser)
      res.status(404).json({ status: false, message: "user id not found" });
    else {
      let credits = await getCreditByUser(userId);
      let total_credit = 0;
      if (credits.length > 0) {
        credits.forEach((credit) => {
          total_credit += credit.credit_available;
        });
        res.json({ status: true, data: total_credit });
      } else {
        res.json({ status: false, message: "user has no credits" });
      }
    }
  } catch (e) {
    res.json({ status: false, message: e.message });
  }
};

controllerMethods.createUser = async (req, res) => {
  try {
    const { body } = req;
    if (
      !body.first_name ||
      !body.last_name ||
      !body.email_address ||
      !body.password ||
      !body.address ||
      !body.credit_card
    )
      res.status(400).json({
        success: false,
        message: "Not all required properties have been provided.",
      });
    else {
      // encrypt password
      const salt = genSaltSync(10);
      body.password = hashSync(body.password, salt);

      let results = await userService.createUser(body);
      res.status(201).json({ success: true, data: results });
    }
  } catch (e) {
    //check the error code coming back from MySQL
    if (e.code === "ER_DUP_ENTRY")
      res.status(400).json({
        success: false,
        message: "User with this email already exists.",
      });
    else {
      console.log(e.message);
      res.status(500).json({
        success: false,
        message: e.message,
      });
    }
  }
};

controllerMethods.updateUser = async (req, res) => {
  try {
    const { body } = req;
    const { userId } = req.params;
    if (
      !body.first_name ||
      !body.last_name ||
      !body.email_address ||
      !body.password ||
      !body.address ||
      !body.credit_card ||
      !userId
    )
      res.status(400).json({
        success: false,
        message: "Not all required properties have been provided.",
      });
    else if (req.userId !== userId) {
      res.status(401).json({
        success: false,
        message: "Current user is not authorized to make update.",
      });
    } else {
      // encrypt password
      const salt = genSaltSync(10);
      body.password = hashSync(body.password, salt);

      let results = await userService.updateUser(body, userId);
      if (results) {
        res.json({ success: true, data: results });
      } else {
        res.status(404).json({ success: false, data: "No user found." });
      }
    }
  } catch (e) {
    //check the error code coming back from MySQL
    if (e.code === "ER_DUP_ENTRY")
      res.status(400).json({
        success: false,
        message: "User with this email already exists.",
      });
    else {
      console.log(e.message);
      res.status(500).json({
        success: false,
        message: e.message,
      });
    }
  }
};

controllerMethods.deleteUser = async (req, res) => {
  try {
    const { userId } = req.params;
    if (req.userId !== userId) {
      res.status(401).json({
        success: false,
        message: "Current user is not authorized to make delete.",
      });
    } else {
      let results = await userService.deleteUser(userId);
      if (results) {
        res.json({ success: true, message: "Delete successful." });
      } else {
        res.status(404).json({ success: false, data: "No user found." });
      }
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

controllerMethods.login = async (req, res) => {
  try {
    const { body } = req;
    let results = await userService.getUserByEmail(body);
    if (!results)
      res.status(404).json({ success: false, data: "No user found." });
    else {
      const result = compareSync(body.password, results.password);
      if (result) {
        results.password = undefined; // don't pass user password in
        const jsontoken = sign({ userId: results.id }, process.env.JWT_KEY);
        res.json({
          success: true,
          message: "Login successful.",
          data: {
            user_id: results.id,
            token: jsontoken,
          },
        });
      } else {
        res.status(401).json({
          success: false,
          message: "Invalid email or password.",
        });
      }
    }
  } catch (e) {
    console.log(e.message);
    res.status(500).json({
      success: false,
      message: e.message,
    });
  }
};

module.exports = controllerMethods;
