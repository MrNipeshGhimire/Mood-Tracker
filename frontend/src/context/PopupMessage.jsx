// components/PopupMessage.jsx
import React from "react";

const PopupMessage = ({ message, onClose }) => {
  return (
    <div className="fixed top-4 right-4 bg-green-500 text-white px-6 py-3 rounded shadow-lg z-50 transition duration-300">
      <div className="flex items-center justify-between">
        <span>{message}</span>
        <button className="ml-4 font-bold" onClick={onClose}>×</button>
      </div>
    </div>
  );
};

export default PopupMessage;
