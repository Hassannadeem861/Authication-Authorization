import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../modules/auth-module.mjs";
import dotenv from "dotenv";
import nodemailer from "nodemailer";

dotenv.config();

const register = async (req, res) => {
    try {
        const { name, email, password} = req.body;
        // console.log("name, email, password, role :", req.body);


        if (!name || !email || !password) {
            return res.status(403).json({ message: "Required parameters missing" });
        }

        const userEmail = await User.findOne({ email: email.toLowerCase() });
        // console.log("userEmail :", userEmail);

        if (userEmail) {
            return res.status(403).json({ message: "User email already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        // console.log("hashedPassword :", hashedPassword);

        const userCreated = await User.create({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            // role: role || "user",
        });

        // console.log("userCreated: ", userCreated);

        res.status(201).json({ message: "Registration successful", userCreated });
    } catch (error) {
        // next(error);
        res.status(500).json({ message: "Internal server error", error });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        // console.log("email, password ", req.body);

        if (!email || !password) {
            return res
                .status(403)
                .json({ message: "Email and password are required" });
        }

        const user = await User.findOne({ email: email.toLowerCase() }).select(
            "+password"
        );
        // console.log("login user :", user);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(404).json({ message: "Invalid email or password" });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "15h" }
        );
        // console.log("Login token :", token);
        res
            .status(201)
            .cookie("Hassan_Nadeem", token, {
                maxage: 15 * 24 * 60 * 60 * 1000,
                sameSite: "none",
                httpOnly: true,
                secure: true,
            })
            .json({ message: `Login successful in ${user.name}`, token, user });
    } catch (error) {
        // next(error);
        res.status(500).json({ message: "Internal server error", error });
    }
};

const getAllUsers = async (req, res) => {
    try {
        const findAllUsers = await User.find();
        res.status(200).json({ message: "Get all users successfully", findAllUsers });
    } catch (error) {
        console.log("Error fetching users: ", error);
        res.status(500).json({ message: "Server error" });
    }
};

const updatePassword = async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    // Check if both currentPassword and newPassword are provided
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: "Current password and new password are required" });
    }

    const userId = req.params.id;

    try {
        // Find the user by ID
        const user = await User.findById(userId).select(
            "+password"
        );;
        // console.log("user: ", user);


        // If user is not found, return a 404 error
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }


        // Check if the user has a password field
        if (!user.password) {
            return res.status(400).json({ message: "User does not have a password set" });
        }

        // Compare the current password with the user's stored password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        // console.log("isMatch: ", isMatch);

        // If the passwords do not match, return a 400 error
        if (!isMatch) {
            return res.status(400).json({ message: "Current password is incorrect" });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password with the new hashed password
        user.password = hashedPassword;
        await user.save();

        // Respond with success
        res.status(200).json({ message: "Password updated successfully", user });
    } catch (error) {
        console.error("Error updating password: ", error);
        res.status(500).json({ message: "Server error" });
    }
};

const forgetPassword = async (req, res) => {
    try {
        const { email } = req.body;


        if (!email) {
            return res.status(400).json({ message: "Please provide an email address" });
        }

        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({ message: "User not found. Please register first." });
        }


        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        // Set up nodemailer
        const transporter = nodemailer.createTransport({
            service: "gmail",
            secure: true,
            auth: {
                user: process.env.MY_EMAIL,
                pass: process.env.MY_PASSWORD
            }
        });

        // Prepare email details
        const mailOptions = {
            from: "hr@techicoders.com",
            to: email,
            subject: "Password Reset Request",
            text: `Please click on the link to reset your password: ${process.env.SERVER_URL}/reset-password/${token}`
        };

        // Send email
        await transporter.sendMail(mailOptions);

        // Respond with success
        return res.status(200).json({ message: "Password reset link has been sent to your email." });
    } catch (error) {
        console.error("Forget password error: ", error);
        return res.status(500).json({ message: "An error occurred while processing your request." });
    }
};

const resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;


        if (!password) {
            return res.status(400).json({ message: "Please provide a new password." });
        }

        if (password.length < 8) {
            return res.status(400).json({ message: "Password must be at least 8 characters long." });
        }


        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        // console.log("Decoded token:", decodedToken);


        const user = await User.findOne({ email: decodedToken.email });
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }


        const hashedPassword = await bcrypt.hash(password, 10);


        user.password = hashedPassword;
        await user.save();


        return res.status(200).json({ message: "Password has been reset successfully." });

    } catch (error) {
        // Handle token expiration or invalid token errors
        if (error.name === "TokenExpiredError") {
            return res.status(400).json({ message: "Token has expired. Please request a new password reset link." });
        } else if (error.name === "JsonWebTokenError") {
            return res.status(400).json({ message: "Invalid token. Please request a new password reset link." });
        }

        console.error("Reset password error:", error);
        return res.status(500).json({ message: "An error occurred while resetting the password." });
    }
};

export { register, login, getAllUsers, updatePassword, forgetPassword, resetPassword };