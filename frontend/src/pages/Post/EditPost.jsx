import React, { useContext, useState } from "react";
import { useLocation, useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { FaSave, FaTimes } from "react-icons/fa";
import Navbar from "../../components/Navbar";
import AuthContext from "../../context/AuthContext";
import Footer from "../home/Footer";


const EditPost = () => {
  const { id } = useParams(); // Get post ID
  const navigate = useNavigate();
  const location = useLocation(); // Get passed state
  const [content, setContent] = useState(location.state?.content || ""); // Set initial content

  const { user, isAuthenticated } = useContext(AuthContext);

// Redirect if not logged in
if (!isAuthenticated) {
  navigate("/login");
}

  const handleUpdate = async () => {
    try {
      await axios.put(`http://127.0.0.1:8000/api/posts/${user.id}/`, { content, id });
      navigate(-1); // Go back after updating
    } catch (err) {
      console.error("Failed to update the post.");
    }
  };

  return (
    <>
      <Navbar />
      <div className="flex justify-center items-center min-h-screen bg-gray-100">
        <div className="bg-white p-8 shadow-lg rounded-lg max-w-lg w-full">
          <h2 className="text-2xl font-semibold text-gray-800 mb-4 text-center">Edit Post</h2>
          
          {/* Input Area */}
          <textarea
            className="w-full h-40 p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 resize-none"
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />

          {/* Buttons */}
          <div className="flex justify-between mt-6">
            <button
              onClick={() => navigate(-1)}
              className="flex items-center px-4 py-2 text-gray-700 bg-gray-200 hover:bg-gray-300 rounded-lg transition"
            >
              <FaTimes className="mr-2" /> Cancel
            </button>
            <button
              onClick={handleUpdate}
              className="flex items-center px-4 py-2 text-white bg-blue-500 hover:bg-blue-600 rounded-lg transition"
            >
              <FaSave className="mr-2" /> Save
            </button>
          </div>
        </div>
      </div>
      <Footer/>
    </>
  );
};

export default EditPost;
