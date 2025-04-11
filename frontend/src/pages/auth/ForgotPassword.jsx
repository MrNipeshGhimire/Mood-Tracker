import { useState } from "react";
import { motion } from "framer-motion";
import { Toaster, toast } from "react-hot-toast";
import axios from "axios";
import { useNavigate } from "react-router-dom";

export default function ForgotPassword() {
   const navigate = useNavigate()
  const [step, setStep] = useState(1);
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const API_URL = "http://127.0.0.1:8000/api"; // Replace with your backend URL

  // Step 1: Request OTP
  const handleRequestOTP = async () => {
    setLoading(true);
    try {
      await axios.post(`${API_URL}/forgot-password/`, { email });
      toast.success("OTP sent to your email!");
      setStep(2);
    } catch (error) {
      toast.error(error.response?.data?.error || "Something went wrong!");
    }
    setLoading(false);
  };

  // Step 2: Verify OTP
  const handleVerifyOTP = async () => {
    setLoading(true);
    try {
      await axios.post(`${API_URL}/verify-otp/`, { email, otp });
      toast.success("OTP Verified! Enter new password.");
      setStep(3);
    } catch (error) {
      toast.error(error.response?.data?.error || "Invalid OTP!");
    }
    setLoading(false);
  };

  // Step 3: Reset Password
  const handleResetPassword = async () => {
    setLoading(true);
    try {
      await axios.post(`${API_URL}/reset-password/`, { email, otp, new_password: newPassword });
      toast.success("Password reset successful!");
      setStep(1);
      setEmail("");
      setOtp("");
      setNewPassword("");
      navigate("/login")
    } catch (error) {
      toast.error(error.response?.data?.error || "Error resetting password!");
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <Toaster />
      <motion.div
        className="bg-white shadow-lg rounded-2xl p-8 w-full max-w-md"
        initial={{ opacity: 0, y: -50 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <h2 className="text-2xl font-bold text-center mb-6">
          {step === 1 ? "Forgot Password" : step === 2 ? "Verify OTP" : "Reset Password"}
        </h2>

        {step === 1 && (
          <>
            <input
              type="email"
              placeholder="Enter your email"
              className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <button
              onClick={handleRequestOTP}
              className="w-full mt-4 bg-primaryBg text-white py-2 rounded-lg hover:bg-primaryBg transition"
              disabled={loading}
            >
              {loading ? "Sending OTP..." : "Send OTP"}
            </button>
          </>
        )}

        {step === 2 && (
          <>
            <input
              type="text"
              placeholder="Enter OTP"
              className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
            />
            <button
              onClick={handleVerifyOTP}
              className="w-full mt-4 bg-green-500 text-white py-2 rounded-lg hover:bg-green-600 transition"
              disabled={loading}
            >
              {loading ? "Verifying..." : "Verify OTP"}
            </button>
          </>
        )}

        {step === 3 && (
          <>
          <label>Enter new Password</label>
            <input
              type="password"
              className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
            <button
              onClick={handleResetPassword}
              className="w-full mt-4 bg-primaryBg text-white py-2 rounded-lg hover:bg-purple-600 transition"
              disabled={loading}
            >
              {loading ? "Resetting..." : "Reset Password"}
            </button>
          </>
        )}
      </motion.div>
    </div>
  );
}
