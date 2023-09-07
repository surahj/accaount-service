import express from "express";
import {
  getAllUsers,
  getSingleUser,
  updateUser,
  deleteUser,
  deactivate,
} from "./users.controllers.js";

const userRouter = express.Router();

userRouter.get("/", getAllUsers);
userRouter.get("/:id", getSingleUser);
userRouter.patch("/:id", updateUser);
userRouter.patch("/deactivate/:id", deactivate);
userRouter.delete("/:id", deleteUser);

export default userRouter;
