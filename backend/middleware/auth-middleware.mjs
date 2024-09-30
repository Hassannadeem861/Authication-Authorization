import jwt from "jsonwebtoken";
import User from "../modules/auth-module.mjs";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

const authMiddleware = async (req, res, next) => {
  
  // const token = req.cookies["Hassan_Nadeem"];
  const token = req.header('Authorization')
  console.log("middleware token :", token);
  // .replace('Bearer ', '');  // Remove "Bearer " prefix from the token

  if (!token) {
    return res.status(200).json({ message: "Token not provided" });
  }

  try {
    const verifyToken = jwt.verify(token, process.env.JWT_SECRET);
    // console.log("verifyToken :", verifyToken);
    req.user = verifyToken;
    console.log("middleware verifyToken :", verifyToken);


    next();
  } catch (error) {
    return res.status(200).json({ message: "Invalid or expired token." });
  }
};

const adminMiddleWare = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId);
    console.log("adminMiddleWare :", user);

    if (user.role !== "admin") {
      return res.status(401).json({ message: "This user is not admin" });
    }
    next();
  } catch (error) {
    return res.status(500).json({ message: "Admin middleware error", error });
  }
};

export { authMiddleware, adminMiddleWare };