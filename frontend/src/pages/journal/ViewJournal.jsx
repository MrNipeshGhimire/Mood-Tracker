import React, { useState, useEffect } from "react";
import Navbar from "../../components/Navbar";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import Footer from "../home/Footer";
import { FaEdit, FaTrash } from "react-icons/fa";

const ViewJournal = () => {
  const { id } = useParams(); // User ID from the URL
  const navigate = useNavigate();
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch journal entries for the user
  useEffect(() => {
    const fetchPosts = async () => {
      try {
        const response = await axios.get(`http://127.0.0.1:8000/api/journal_entry/`+id+`/`); // User ID is hardcoded to 1
        setPosts(response.data.journal_entries); // Assuming the API returns 'journal_entries'
      } catch (err) {
        setError("Failed to fetch journal entries.");
      } finally {
        setLoading(false);
      }
    };

    fetchPosts();
  }, []);

  // Handle delete functionality with confirmation
  const handleDelete = async (postId) => {
    const confirmDelete = window.confirm("Are you sure you want to delete this journal entry?");
    if (!confirmDelete) return;

    try {
      await axios.delete(`http://127.0.0.1:8000/api/journal_entry/`+id+`/`, {
        data: { journal_id: postId }, // Send the journal ID in the request body
      });

      setPosts(posts.filter((post) => post.id !== postId)); // Remove the post from UI after deletion
      alert("Journal entry deleted successfully!");
    } catch (err) {
      setError("Failed to delete the journal entry.");
    }
  };

  // Navigate to Edit Journal page
  const handleEdit = (post) => {
    navigate(`/editJournal/${post.id}`, { state: { post } });
  };

  if (loading) return <div>Loading...</div>;
  if (error) return <div>{error}</div>;

  return (
    <>
      <Navbar />
      <div className="flex flex-col items-center py-8 bg-gray-100 min-h-screen">
        <h1 className="text-3xl font-semibold mb-8 text-center">Your Daily Mood Journal Entries</h1>
        <div className="w-full max-w-4xl px-4">
          {posts.length > 0 ? (
            posts.map((post) => (
              <div key={post.id} className="mb-4 p-6 bg-white shadow-lg rounded-lg flex flex-col space-y-4">
                {/* Date on top left */}
                <div className="flex justify-between items-center">
                  <span className="text-sm text-gray-500">{post.date}</span>
                </div>

                {/* Journal Content */}
                <div className="text-lg text-gray-700">{post.journal_description}</div>

                {/* Edit & Delete Buttons */}
                <div className="flex justify-end space-x-4 mt-3">
                  <button onClick={() => handleEdit(post)} className="text-blue-500 hover:text-blue-700 flex items-center">
                    <FaEdit className="mr-1" /> Edit
                  </button>
                  <button onClick={() => handleDelete(post.id)} className="text-red-500 hover:text-red-700 flex items-center">
                    <FaTrash className="mr-1" /> Delete
                  </button>
                </div>
              </div>
            ))
          ) : (
            <p>No journal entries found.</p>
          )}
        </div>
      </div>
      <Footer/>
    </>
  );
};

export default ViewJournal;
