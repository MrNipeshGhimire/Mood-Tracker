import { useState, useEffect, useContext } from "react";
import AuthContext from "../../context/AuthContext";
import axios from "axios";
import Navbar from "../../components/Navbar";
import Footer from "../home/Footer";

function ChangePassword() {
  const { user } = useContext(AuthContext);
  
  const [formData, setFormData] = useState({
    old_password: "",
    new_password: "",
    confirm_password: "",
  });

  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    // Reset error/success messages
    setError(null);
    setSuccess(null);

    // Validate if passwords match
    if (formData.new_password !== formData.confirm_password) {
      setError("New password and confirm password do not match.");
      return;
    }

    // Make API call to change password
    axios
      .post(`http://127.0.0.1:8000/api/user/${user.id}/change-password/`, formData)
      .then((response) => {
        setSuccess("Password updated successfully!");
        setFormData({ old_password: "", new_password: "", confirm_password: "" });
      })
      .catch((error) => {
        setError(error.response?.data?.message || "Failed to change password.");
      });
  };

  return (
   <>
   <Navbar/>
   <div className="max-w-md mx-auto mt-10 p-6 bg-white shadow-lg rounded-lg">
      <h2 className="text-2xl font-bold text-center text-primaryBg mb-6">Change Password</h2>

      {error && <div className="bg-red-500 text-white p-3 mb-4 rounded">{error}</div>}
      {success && <div className="bg-green-500 text-white p-3 mb-4 rounded">{success}</div>}

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Old Password */}
        <div>
          <label className="block text-gray-700 font-medium">Old Password</label>
          <input
            type="password"
            name="old_password"
            value={formData.old_password}
            onChange={handleChange}
            className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primaryBg"
            placeholder="Enter old password"
            required
          />
        </div>

        {/* New Password */}
        <div>
          <label className="block text-gray-700 font-medium">New Password</label>
          <input
            type="password"
            name="new_password"
            value={formData.new_password}
            onChange={handleChange}
            className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primaryBg"
            placeholder="Enter new password"
            required
          />
        </div>

        {/* Confirm New Password */}
        <div>
          <label className="block text-gray-700 font-medium">Confirm New Password</label>
          <input
            type="password"
            name="confirm_password"
            value={formData.confirm_password}
            onChange={handleChange}
            className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primaryBg"
            placeholder="Confirm new password"
            required
          />
        </div>

        {/* Submit Button */}
        <div className="flex justify-center">
          <button
            type="submit"
            className="bg-primaryBg text-white px-6 py-2 rounded-lg hover:bg-secondary transition-all"
          >
            Change Password
          </button>
        </div>
      </form>
    </div>
    <Footer/>
   </> 
  );
}

export default ChangePassword;
