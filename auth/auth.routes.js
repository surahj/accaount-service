import {
  registerUser, loginUser, logoutUser, protect, updatePassword, forgotPassword, resetPassword
} from "./auth.controllers.js";

import express from "express";

const authRouter = express.Router();

authRouter.post("/register", registerUser);
authRouter.post("/login", loginUser);
authRouter.post("/logout", logoutUser);
authRouter.post("/forgotPassword", forgotPassword);
authRouter.patch("/resetPassword/:token", resetPassword);


authRouter.use(protect);
authRouter.patch("/updatePassword", updatePassword);


export default authRouter;
