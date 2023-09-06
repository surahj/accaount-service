import express from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
// import csurf from "csurf";
import cors from "cors"; 
import helmet from "helmet";
import {
  connectDB,
  authRouter,
  userRouter,
  organizationRouter,
} from "./localImport.js";
dotenv.config();

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(cors());
// app.use(csurf({ cookie: true }));
app.use(helmet());

//Routes go here
app.get("/", (req, res) => {
  res.send("<h1>Welcome</h1>");
});

const basePath = "/api/v1";
app.use(`${basePath}/auth`, authRouter);
app.use(`${basePath}/users`, userRouter);
app.use(`${basePath}/organization`, organizationRouter);

//Connect to the database before listening
const PORT = process.env.PORT || process.env.API_PORT;
console.log("Port: " + PORT);

app.listen(PORT, () => {
  connectDB();
  console.log(`Server is running on PORT ${PORT}`);
});
