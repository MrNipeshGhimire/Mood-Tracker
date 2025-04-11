import React, { useState, useEffect, useContext } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import axios from "axios";
import Navbar from "../../components/Navbar";
import AuthContext from "../../context/AuthContext";
import Footer from "../home/Footer";


const EditJournal = () => {
  const { id } = useParams(); // Journal entry ID from the URL
  const location = useLocation();
  const navigate = useNavigate();
  const [journalDescription, setJournalDescription] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  
  const { user, isAuthenticated } = useContext(AuthContext);

  // Redirect if not logged in
  if (!isAuthenticated) {
    navigate("/login");
  }

  // Fetch the existing journal entry if not passed via navigation state
  useEffect(() => {
    if (location.state?.post) {
      setJournalDescription(location.state.post.journal_description);
      setLoading(false);
    } else {
      const fetchJournal = async () => {
        try {
          const response = await axios.get(`http://127.0.0.1:8000/api/journal_entry/`+id+`/`);
          const journalEntry = response.data.journal_entries.find((entry) => entry.id === parseInt(id));
          if (journalEntry) {
            setJournalDescription(journalEntry.journal_description);
          } else {
            setError("Journal entry not found.");
          }
        } catch (err) {
          setError("Failed to fetch journal entry.");
        } finally {
          setLoading(false);
        }
      };
      fetchJournal();
    }
  }, [id, location.state]);

  // Handle input change
  const handleChange = (e) => {
    setJournalDescription(e.target.value);
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const response = await axios.put(`http://127.0.0.1:8000/api/journal_entry/`+user.id+`/`, {
        journal_id: id,
        journal_description: journalDescription,
      });

      if (response.status === 200) {
        alert("Journal entry updated successfully!");
        navigate(-1); // Go back to the previous page
      }
    } catch (err) {
      setError("Failed to update journal entry.");
    }
  };

  if (loading) return <div className="text-center text-gray-500 mt-10">Loading...</div>;
  if (error) return <div className="text-center text-red-500 mt-10">{error}</div>;

  return (
    <>
      <Navbar />
      <div className="flex justify-center items-center min-h-screen bg-gray-100">
        <div className="w-full max-w-2xl bg-white p-8 shadow-lg rounded-lg">
          <h1 className="text-2xl font-semibold text-center mb-6">Edit Journal Entry</h1>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-gray-700 text-sm font-semibold mb-2">Journal Description</label>
              <textarea
                className="w-full p-3 border border-gray-300 rounded-lg focus:ring focus:ring-blue-300"
                rows="5"
                value={journalDescription}
                onChange={handleChange}
                required
              />
            </div>

            <div className="flex justify-between">
              <button
                type="button"
                onClick={() => navigate(-1)}
                className="bg-gray-400 text-white px-4 py-2 rounded-lg hover:bg-gray-500 transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition"
              >
                Save Changes
              </button>
            </div>
          </form>
        </div>
      </div>
      <Footer/>
    </>
  );
};

export default EditJournal;
