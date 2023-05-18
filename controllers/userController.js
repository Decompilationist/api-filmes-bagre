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
      res.status(404).json({ success: false, message: "usuários não encontrados." });
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
        message: "O usuário atual não está autorizado para dar get nas informações.",
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
        res.status(404).json({ success: false, message: "Nenhum usuário encontrado." });
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
      res.status(404).json({ status: false, message: "id de usuário não encontrado" });
    else {
      let credits = await getCreditByUser(userId);
      let total_credit = 0;
      if (credits.length > 0) {
        credits.forEach((credit) => {
          total_credit += credit.credit_available;
        });
        res.json({ status: true, data: total_credit });
      } else {
        res.json({ status: false, message: "usuário não possui créditos" });
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
        message: "Nem todas as propriedades necessárias foram fornecidas",
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
        message: "Usuário com esse e-mail existente..",
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
        message: "Nem todas as propriedades necessárias foram fornecidas.",
      });
    else if (req.userId !== userId) {
      res.status(401).json({
        success: false,
        message: "Usuário atual não autorizado para executar update.",
      });
    } else {
      // encrypt password
      const salt = genSaltSync(10);
      body.password = hashSync(body.password, salt);

      let results = await userService.updateUser(body, userId);
      if (results) {
        res.json({ success: true, data: results });
      } else {
        res.status(404).json({ success: false, data: "Nenhum usuário encontrado." });
      }
    }
  } catch (e) {
    //check the error code coming back from MySQL
    if (e.code === "ER_DUP_ENTRY")
      res.status(400).json({
        success: false,
        message: "Usuário com esse e-mail existente.",
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
        message: "O usuário atual não é autorizado a deletar.",
      });
    } else {
      let results = await userService.deleteUser(userId);
      if (results) {
        res.json({ success: true, message: "Deletato com sucesso." });
      } else {
        res.status(404).json({ success: false, data: "Nenhum usuário encontrado." });
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
          message: "Logado com sucesso.",
          data: {
            user_id: results.id,
            token: jsontoken,
          },
        });
      } else {
        res.status(401).json({
          success: false,
          message: "Email ou senha inválida.",
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
