import { useState, useEffect, useContext } from "react";
import AuthContext from "../../context/AuthContext";
import axios from "axios";
import Navbar from "../../components/Navbar";
import Footer from "../home/Footer";
import PopupMessage from "../../context/PopupMessage";


function ViewProfile() {
    const { user, isAuthenticated } = useContext(AuthContext);
  
  const [formData, setFormData] = useState({
    first_name: "",
    last_name: "",
    username: "",
    email: "",
  });

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [popup, setPopup] = useState({ visible: false, message: "" });

  const showPopup = (msg) => {
    setPopup({ visible: true, message: msg });
    setTimeout(() => {
      setPopup({ visible: false, message: "" });
    }, 3000); // Auto-close after 3 seconds
  };

  useEffect(() => {
    if (user) {
      // Fetch user details when the component is mounted
      axios
        .get(`http://127.0.0.1:8000/api/user/${user.id}/`)
        .then((response) => {
          const userData = response.data.user;
          setFormData({
            first_name: userData.first_name || "",
            last_name: userData.last_name || "",
            username: userData.username || "",
            email: userData.email || "",
          });
          setLoading(false);
        })
        .catch((error) => {
          setError("Failed to load user data.");
          setLoading(false);
        });
    }
  }, [user]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    // Make PUT request to update user data
    axios
      .put(`http://127.0.0.1:8000/api/user/${user.id}/`, formData)
      .then((response) => {
        showPopup("Profile updated successfully!");
        // Optionally, you can update the user context if needed
      })
      .catch((error) => {
        showPopup("Failed to update profile.");
      });
  };

  // Show a loading indicator or error message while loading
  if (loading) {
    return <div>Loading...</div>;
  }

  if (error) {
    return <div>{error}</div>;
  }

  return (
    <>
    <Navbar/>
    <div className="max-w-2xl mx-auto mt-10 p-6 bg-white shadow-lg rounded-lg">
      <h2 className="text-2xl font-bold text-center text-primaryBg mb-6">User Profile</h2>

      {/* Profile Picture Placeholder */}
      <div className="flex justify-center mb-6">
        <div className="w-24 h-24 flex items-center justify-center rounded-full bg-primaryBg text-white text-3xl font-semibold">
          {user?.username.charAt(0).toUpperCase()}
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* First Name */}
        <div>
          <label className="block text-gray-700 font-medium">First Name</label>
          <input
            type="text"
            name="first_name"
            value={formData.first_name}
            onChange={handleChange}
            className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primaryBg"
            placeholder="Enter first name"
          />
        </div>

        {/* Last Name */}
        <div>
          <label className="block text-gray-700 font-medium">Last Name</label>
          <input
            type="text"
            name="last_name"
            value={formData.last_name}
            onChange={handleChange}
            className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primaryBg"
            placeholder="Enter last name"
          />
        </div>

        {/* Username */}
        <div>
          <label className="block text-gray-700 font-medium">Username</label>
          <input
            type="text"
            name="username"
            value={formData.username}
            onChange={handleChange}
            className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primaryBg"
            placeholder="Enter username"
          />
        </div>

        {/* Email */}
        <div>
          <label className="block text-gray-700 font-medium">Email</label>
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primaryBg"
            placeholder="Enter email"
          />
        </div>

        {/* Save Changes Button */}
        <div className="flex justify-center">
          <button
            type="submit"
            className="bg-primaryBg text-white px-6 py-2 rounded-lg hover:bg-secondary transition-all"
          >
            Save Changes
          </button>
        </div>
      </form>
    </div>
    {popup.visible && (
  <PopupMessage
    message={popup.message}
    onClose={() => setPopup({ visible: false, message: "" })}
  />
)}
    <Footer/>
    </>
  );
}

export default ViewProfile;
