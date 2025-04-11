import React, { useState, useEffect, useContext } from "react";
import { FaUserCircle, FaRegComment } from "react-icons/fa";
import axios from "axios";
import { Link } from "react-router-dom";
import AuthContext from "../../context/AuthContext";
import Navbar from "../../components/Navbar";
import Footer from "../home/Footer";

const PostList = () => {
  const [posts, setPosts] = useState([]);
  const [newComments, setNewComments] = useState({});
  const [activePost, setActivePost] = useState(null);
  const [editComment, setEditComment] = useState({});

  const { user, isAuthenticated } = useContext(AuthContext);

  // Fetch posts from the backend API
  const fetchPosts = async () => {
    try {
      const response = await axios.get("http://127.0.0.1:8000/api/posts/");
      setPosts(response.data.posts);
    } catch (error) {
      console.error("Error fetching posts:", error);
    }
  };

  useEffect(() => {
    fetchPosts();
  }, []);

  const toggleCommentSection = (postId) => {
    setActivePost(activePost === postId ? null : postId);
  };

  const handleCommentChange = (postId, value) => {
    setNewComments({ ...newComments, [postId]: value });
  };

  const handleCommentSubmit = async (postId) => {
    if (newComments[postId]?.trim()) {
      try {
        const response = await axios.post("http://127.0.0.1:8000/api/comments/", {
          user: user.id,
          post: postId,
          content: newComments[postId],
        });

        fetchPosts();
        setNewComments({ ...newComments, [postId]: "" });
      } catch (error) {
        console.error("Error submitting comment:", error);
      }
    }
  };

  const handleCommentEdit = async (commentId, newContent, postId) => {
    try {
      const response = await axios.put(`http://127.0.0.1:8000/api/comments/${commentId}/`, {
        user: user.id,
        content: newContent,
      });

      fetchPosts();
      setEditComment({});
    } catch (error) {
      console.error("Error editing comment:", error);
    }
  };

  const handleCommentDelete = async (commentId, postId) => {
    try {
      await axios.delete(`http://127.0.0.1:8000/api/comments/${commentId}/`, {
        data: { user: user.id },
      });

      fetchPosts();
    } catch (error) {
      console.error("Error deleting comment:", error);
    }
  };

  // Function to format date
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    const today = new Date();
    const diffTime = today - date;
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 0) {
      return "Today";
    } else if (diffDays === 1) {
      return "Yesterday";
    } else if (diffDays < 7) {
      return `${diffDays} days ago`;
    } else {
      return date.toLocaleDateString();
    }
  };

  return (
    <>
      <Navbar />
      {isAuthenticated && (
        <div className="container mx-auto mt-5 ml-5">
          <div className="flex justify-start">
            <Link to="/addPost">
              <button className="bg-primaryBg text-white px-4 py-2 rounded-full hover:bg-blue-600 transition">
                + Create Post
              </button>
            </Link>
          </div>
        </div>
      )}

      <div className="max-w-4xl mx-auto mt-8 space-y-8 mb-7">
        {posts.map((post) => (
          <div key={post.id} className="bg-white p-6 rounded-xl shadow-xl hover:shadow-2xl transition-all ease-in-out duration-300">
            <div className="flex items-center space-x-4">
              <FaUserCircle className="text-5xl text-primaryBg" />
              <div>
                <span className="font-semibold text-lg text-gray-800">Anonymous User</span>
                <p className="text-sm text-gray-500">{formatDate(post.created_at)}</p>
              </div>
            </div>

            <p className="mt-4 text-xl text-gray-700">{post.content}</p>

            <div className="flex justify-between items-center mt-6 text-gray-600">
              <div className="flex items-center space-x-6">
                <div className="flex items-center space-x-3">
                  <FaRegComment
                    className="text-2xl cursor-pointer hover:text-blue-500 transition-all ease-in-out duration-300"
                    onClick={() => toggleCommentSection(post.id)}
                  />
                  <span className="text-lg">{post.comments.length} comments</span>
                </div>
              </div>
            </div>

            {activePost === post.id && (
              <div className="mt-6">
                <div className="space-y-4">
                  {post.comments.map((comment) => (
                    <div key={comment.id} className="bg-gray-100 p-4 rounded-lg shadow-sm">
                      <div className="flex items-center space-x-3">
                        <FaUserCircle className="text-xl text-gray-500" />
                        {/* <span className="font-semibold">{comment.username}</span> */}
                        <span className="font-semibold">Anonymous</span>
                        <span className="text-xs text-gray-400">{formatDate(comment.created_at)}</span>
                      </div>
                      {editComment.id === comment.id ? (
                        <div className="mt-2">
                          <input
                            type="text"
                            defaultValue={comment.content}
                            className="border border-gray-300 p-2 w-full rounded-md"
                            onChange={(e) =>
                              setEditComment({ ...editComment, content: e.target.value })
                            }
                          />
                          <button
                            onClick={() => handleCommentEdit(comment.id, editComment.content, post.id)}
                            className="bg-blue-500 text-white px-6 py-3 mt-2 rounded-lg"
                          >
                            Save
                          </button>
                        </div>
                      ) : (
                        <p className="mt-2 text-gray-600">{comment.content}</p>
                      )}

                      {user.id === comment.user && (
                        <div className="mt-2 flex space-x-4">
                          <button
                            onClick={() => setEditComment({ id: comment.id, content: comment.content })}
                            className="text-blue-500"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => handleCommentDelete(comment.id, post.id)}
                            className="text-red-500"
                          >
                            Delete
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                <div className="mt-6 flex space-x-4">
                  <input
                    type="text"
                    placeholder="Write a comment..."
                    value={newComments[post.id] || ""}
                    onChange={(e) => handleCommentChange(post.id, e.target.value)}
                    className="flex-grow border border-gray-300 rounded-lg p-4 text-lg shadow-sm focus:ring-2 focus:ring-blue-500 transition-all ease-in-out duration-300"
                  />
                  <button
                    className="bg-primaryBg text-white px-6 py-3 rounded-lg text-lg shadow-lg hover:bg-blue-600 transition-all ease-in-out duration-300"
                    onClick={() => handleCommentSubmit(post.id)}
                  >
                    Send
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
      <Footer />
    </>
  );
};

export default PostList;
