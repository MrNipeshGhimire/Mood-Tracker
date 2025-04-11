import React, { useState, useEffect, useRef, useContext } from 'react';
import axios from 'axios';
import AuthContext from "../../context/AuthContext";
import { FiSend, FiArrowLeft } from 'react-icons/fi';
import { BsRobot, BsPerson } from 'react-icons/bs';
import { useNavigate } from 'react-router-dom';

const ChatWithAI = ({ userId }) => {
  const [message, setMessage] = useState('');
  const [conversation, setConversation] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef(null);
  const { user } = useContext(AuthContext);
  const navigate = useNavigate();

  // Fetch chat history in chronological order
  useEffect(() => {
    const fetchChatHistory = async () => {
      try {
        const response = await axios.get(`http://127.0.0.1:8000/api/chat/${user.id}/`);
        const orderedChats = response.data.chats.flatMap(chat => [
          { role: 'user', content: chat.message },
          { role: 'ai', content: chat.response }
        ]);
        setConversation(orderedChats);
      } catch (error) {
        console.error("Error fetching chat history:", error);
      }
    };
    fetchChatHistory();
  }, [user.id]);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [conversation]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!message.trim() || isLoading) return;

    setIsLoading(true);
    setConversation(prev => [...prev, { role: 'user', content: message }]);

    try {
      const response = await axios.post(
        `http://127.0.0.1:8000/api/chat/${user.id}/`,
        { message }
      );
      setConversation(prev => [...prev, { role: 'ai', content: response.data.ai_response }]);
    } catch (error) {
      console.error("Error:", error);
      setConversation(prev => [...prev, { 
        role: 'ai', 
        content: "⚠️ Sorry, I couldn't process your request. Please try again." 
      }]);
    } finally {
      setIsLoading(false);
      setMessage('');
    }
  };

  return (
<div className="flex flex-col h-screen bg-gray-50 mx-auto border-x border-gray-200 shadow-sm" style={{ maxWidth: '900px' }}>      {/* Header with back button */}
      <header className="bg-white border-b border-gray-200 py-3 px-4 flex items-center">
        <button 
          onClick={() => navigate('/')} 
          className="flex items-center text-gray-600 hover:text-blue-500 mr-2"
        >
          <FiArrowLeft className="mr-1" />
          <span className="text-sm">Back to Home</span>
        </button>
        <div className="flex items-center space-x-2 ml-auto">
          <BsRobot className="text-blue-500 text-lg" />
          <h1 className="text-primaryBg font-semibold text-gray-800">Mental Health Assistant</h1>
        </div>
      </header>

      {/* Chat Container */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-white">
        {conversation.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center p-4">
            <BsRobot className="text-3xl text-gray-300 mb-3" />
            <h3 className="text-lg font-medium text-gray-500">How can I help you today?</h3>
            <p className="text-gray-400 mt-1 text-sm">Share what's on your mind</p>
          </div>
        ) : (
          conversation.map((msg, index) => (
            <div
              key={index}
              className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} mb-3`}
            >
              <div className={`max-w-[85%] flex ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                <div className={`flex-shrink-0 mx-2 mt-1 ${msg.role === 'user' ? 'text-primaryBg' : 'text-green-500'}`}>
                  {msg.role === 'user' ? <BsPerson size={25} /> : <BsRobot size={25} />}
                </div>
                <div
                  className={`rounded-lg p-3 ${msg.role === 'user'
                    ? 'bg-primaryBg text-white rounded-br-none'
                    : 'bg-gray-100 text-gray-800 rounded-bl-none'
                  }`}
                >
                  <p className="whitespace-pre-wrap text-sm">{msg.content}</p>
                </div>
              </div>
            </div>
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      {/* Input Area - Updated */}
<div className="bg-white border-t border-gray-200 p-4">
  <form onSubmit={handleSubmit} className="flex items-center gap-3">
    <div className="flex-1 relative">
      <input
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Message Mental Health Assistant..."
        className="w-full border border-gray-300 rounded-xl px-5 py-4 pr-12 text-base focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-sm"
        disabled={isLoading}
      />
      <button
        type="submit"
        disabled={isLoading || !message.trim()}
        className="absolute right-2 top-1/2 transform -translate-y-1/2 bg-blue-500 hover:bg-blue-600 text-white p-2 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 transition-colors"
      >
        <FiSend className="h-5 w-5" />
      </button>
    </div>
  </form>
  <p className="text-xs text-gray-500 mt-2 text-center">
    Mental Health Assistant may produce inaccurate information
  </p>
</div>
    </div>
  );
};

export default ChatWithAI;