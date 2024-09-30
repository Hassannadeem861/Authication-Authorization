import express from "express";
import {
  register,
  login,
  getAllUsers,
  updatePassword,
  forgetPassword,
  resetPassword
} from "../controllers/auth.mjs";
// import { authMiddleware, adminMiddleWare } from "../middleware/auth-middleware.mjs";
const router = express.Router();


router.post("/register", register);
router.post("/login", login);
router.put("/update-password/:id", updatePassword);
router.post("/forget-password", forgetPassword);
router.post("/reset-password/:token", resetPassword);
router.get("/get-all-users", getAllUsers);


export default router;
