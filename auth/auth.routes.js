import { registerUser, loginUser, logoutUser, protect, updatePassword } from "./auth.controllers.js";

import express from "express";

const authRouter = express.Router();

authRouter.post("/register", registerUser);
authRouter.post("/login", loginUser);
authRouter.post("/logout", logoutUser);

authRouter.use(protect);
authRouter.patch("/updatePassword", updatePassword);


export default authRouter;
