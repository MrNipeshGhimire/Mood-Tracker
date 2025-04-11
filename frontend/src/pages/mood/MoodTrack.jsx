import { useState, useContext } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { useNavigate,Link } from "react-router-dom";
import AuthContext from "../../context/AuthContext";
import Navbar from "../../components/Navbar";
import Footer from "../home/Footer";


const MoodTrack = () => {
  const [mood, setMood] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  
  const { user, isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();

  // Redirect if not logged in
  if (!isAuthenticated) {
    navigate("/login");
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const authTokens = JSON.parse(localStorage.getItem("authTokens")); // Get tokens
      
      const response = await axios.post(
        "http://127.0.0.1:8000/api/mood_entry/",
        { mood_description: mood,
          user: user.id
         },
        {
          // headers: {
          //   "Content-Type": "application/json",
          //   Authorization: `Bearer ${authTokens?.access}`, // Using access token
          // },
        }
      );

      setMood(""); // Clear input on success
      setSuccess("Mood submitted successfully! 🎉");
    } catch (err) {
      setError(err.response?.data?.error || "Failed to submit mood.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Navbar />
      <div className="flex flex-col justify-start items-center h-screen bg-gray-100 pt-16">

      <Link to={"/viewReport/"+user.id}>
      <button className="absolute top-8 right-6 bg-primaryBg text-white py-2 px-4 mt-20 mr-1 rounded-lg hover:bg-blue-600 transition">
          View Report
        </button>
        </Link>

        <motion.div
          className="text-5xl mb-4"
          animate={{ rotate: [0, 10, -10, 0] }}
          transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
        >
          😊
        </motion.div>
        <motion.div
          className="p-6 w-96 shadow-xl rounded-2xl bg-white"
          animate={{ y: [0, -5, 0] }}
          transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
        >
          <h1 className="text-2xl font-semibold mb-4 text-center">
            How are you feeling today?
          </h1>
          {success && <p className="text-green-500 text-center mb-2">{success}</p>}
          {error && <p className="text-red-500 text-center mb-2">{error}</p>}
          <form onSubmit={handleSubmit} method="POST">
            <div className="flex flex-col">
              <textarea
                placeholder="Enter your mood..."
                value={mood}
                name="mood_description"
                onChange={(e) => setMood(e.target.value)}
                className="mb-4 w-full p-3 h-24 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none" required
              />
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-primaryBg text-white py-2 rounded-lg hover:hoverBg transition"
              >
                {loading ? "Submitting..." : "Submit"}
              </button>
            </div>
          </form>
        </motion.div>
      </div>
      <Footer/>
    </>
  );
};

export default MoodTrack;
