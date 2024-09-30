import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, index: true, trim: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    // password: { type: String, required: true, select: false},
    // role: { type: String, default: "user" },
    role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' },  // Role reference
  },
  { timestamps: true }
);

const User = mongoose.model("Auth", userSchema);
export default User;