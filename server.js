const express = require("express");
require("dotenv").config();
const cors = require("cors");

const v1UserRouter = require("./v1/routes/userRoutes");
const v1MovieRouter = require("./v1/routes/movieRoutes");
const v1TheatreRouter = require("./v1/routes/theatreRoutes");
const v1TicketRouter = require("./v1/routes/ticketRoutes");
const v1ShowingRouter = require("./v1/routes/showingRoutes");
const v1SeatRouter = require("./v1/routes/seatRoutes");
const v1PaymentRouter = require("./v1/routes/paymentRoutes");
const v1RefundRouter = require("./v1/routes/refundRoutes");
const v1EmailRouter = require("./v1/routes/emailRoutes");

const app = express();
const PORT = process.env.APP_PORT || 5000;

app.use(express.json());
app.use(cors());

app.use("/api/v1/users", v1UserRouter);
app.use("/api/v1/movies", v1MovieRouter);
app.use("/api/v1/theatres", v1TheatreRouter);
app.use("/api/v1/tickets", v1TicketRouter);
app.use("/api/v1/showings", v1ShowingRouter);
app.use("/api/v1/seats", v1SeatRouter);
app.use("/api/v1/payments", v1PaymentRouter);
app.use("/api/v1/refunds", v1RefundRouter);
app.use("/api/v1/emails", v1EmailRouter);

app.listen(PORT, () => {
  console.log(`API is listening on port ${PORT}`);
});
