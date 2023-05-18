const { verify } = require("jsonwebtoken");

const checkToken = (req, res, next) => {
  // this function will check whether the user is authenticated and only allow access to the next function if so
  let token = req.get("authorization");
  if (token) {
    //get token starting at index 7 (first 6 characters are "Bearer ")
    token = token.slice(7);
    verify(token, process.env.JWT_KEY, (err, decoded) => {
      if (err)
        res
          .status(403)
          .json({ success: false, message: "Failed to authenticate token." });
      else {
        // save the userId to the request to use in other routes
        req.userId = decoded.userId;
        next();
      }
    });
  } else {
    res
      .status(401)
      .json({ success: false, message: "No JSON token provided." });
  }
};

const checkUserId = (req, res, next) => {
  // this function will check the userId from the token and pass to the next function whether logged in or not
  let token = req.get("authorization");
  if (token) {
    //get token starting at index 7 (first 6 characters are "Bearer ")
    token = token.slice(7);
    verify(token, process.env.JWT_KEY, (err, decoded) => {
      if (!err)
        // save the userId to the request to use in other routes
        req.userId = decoded.userId;
    });
  }
  next();
};

module.exports = { checkToken, checkUserId };
