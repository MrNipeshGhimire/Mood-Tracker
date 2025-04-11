import React, { useState, useEffect, useContext } from "react";
import Navbar from "../../components/Navbar";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { FaComment, FaEdit, FaTrash } from "react-icons/fa";
import AuthContext from "../../context/AuthContext";
import Footer from "../home/Footer";

const ViewPost = () => {
  const { id } = useParams(); // User ID from the URL
  const navigate = useNavigate();
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [openComments, setOpenComments] = useState({});

  const { user, isAuthenticated } = useContext(AuthContext);

  // Redirect if not logged in
  useEffect(() => {
    if (!isAuthenticated) {
      navigate("/login");
    }
  }, [isAuthenticated, navigate]);

  // Fetch posts along with comments
  useEffect(() => {
    fetchPosts();
  }, [id]);

  const fetchPosts = async () => {
    try {
      const response = await axios.get(`http://127.0.0.1:8000/api/posts/${id}/`);
      setPosts(response.data.posts); // Assuming API returns 'posts'
    } catch (err) {
      setError("Failed to fetch posts.");
    } finally {
      setLoading(false);
    }
  };

  // Handle delete functionality
  const handleDelete = async (postId) => {
    const isConfirmed = window.confirm("Are you sure you want to delete this post?");
    if (!isConfirmed) return;

    try {
      await axios.delete(`http://127.0.0.1:8000/api/posts/${user.id}/`, {
        data: { post_id: postId },
      });

      alert("Post deleted successfully");
      fetchPosts();
    } catch (error) {
      alert("Failed to delete the post.");
    }
  };

  // Navigate to Edit Post page with post content
  const handleEdit = (post) => {
    navigate(`/editPost/${post.id}`, { state: { content: post.content } });
  };

  // Toggle comments section
  const toggleComments = (postId) => {
    setOpenComments((prev) => ({
      ...prev,
      [postId]: !prev[postId],
    }));
  };

  if (loading) return <div className="text-center mt-10 text-lg text-gray-700">Loading...</div>;
  if (error) return <div className="text-center mt-10 text-lg text-red-500">{error}</div>;

  return (
    <>
      <Navbar />
      <div className="flex flex-col items-center py-10 bg-gray-50 min-h-screen">
        <h1 className="text-4xl font-bold mb-10 text-center text-gray-800">Your Posts</h1>
        <div className="w-full max-w-3xl px-4">
          {posts.length > 0 ? (
            posts.map((post) => (
              <div
                key={post.id}
                className="mb-6 p-6 bg-white shadow-md rounded-2xl border border-gray-200 hover:shadow-xl transition-all"
              >
                {/* Post Header - Date */}
                <div className="text-sm text-gray-500">{new Date(post.created_at).toLocaleString()}</div>

                {/* Post Content */}
                <div className="text-lg text-gray-800 mt-4">{post.content}</div>

                {/* Actions - Comment, Edit, Delete */}
                <div className="flex justify-between items-center mt-5">
                  {/* Comment Icon with count */}
                  <button
                    onClick={() => toggleComments(post.id)}
                    className="flex items-center space-x-2 text-gray-600 hover:text-blue-600 transition-all"
                  >
                    <FaComment className="text-lg" />
                    <span className="font-medium">{post.comments.length} Comments</span>
                  </button>

                  {/* Edit & Delete Icons */}
                  <div className="flex space-x-4">
                    <button
                      onClick={() => handleEdit(post)}
                      className="text-gray-600 hover:text-green-500 transition-all"
                    >
                      <FaEdit className="text-lg" />
                    </button>
                    <button
                      onClick={() => handleDelete(post.id)}
                      className="text-gray-600 hover:text-red-500 transition-all"
                    >
                      <FaTrash className="text-lg" />
                    </button>
                  </div>
                </div>

                {/* Comments Section */}
                {openComments[post.id] && (
                  <div className="mt-4 bg-gray-100 p-4 rounded-xl">
                    <h3 className="text-sm font-semibold mb-3">Comments:</h3>
                    {post.comments.length > 0 ? (
                      post.comments.map((comment) => (
                        <div key={comment.id} className="text-sm text-gray-700 border-b py-2">
                          {/* <strong className="text-gray-800">{comment.username}:</strong> {comment.content} */}
                          <strong className="text-gray-800">Anonymous :</strong> {comment.content}

                        </div>
                      ))
                    ) : (
                      <p className="text-gray-500">No comments yet.</p>
                    )}
                  </div>
                )}
              </div>
            ))
          ) : (
            <p className="text-lg text-gray-600 text-center">No posts found.</p>
          )}
        </div>
      </div>
      <Footer/>
    </>
  );
};

export default ViewPost;
