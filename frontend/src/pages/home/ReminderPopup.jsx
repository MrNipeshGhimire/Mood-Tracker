// import { useEffect, useState } from "react";
// import { AiOutlineClose } from "react-icons/ai";

// // Ensure you have a sound file to use (e.g., alarm.mp3)
// import alarmSound from "../../assets/alarm.mp3";  // Path to your sound file

// const ReminderPopup = ({ userId }) => {
//   const [showPopup, setShowPopup] = useState(false);
//   const [audio] = useState(new Audio(alarmSound));  // Initialize audio element with the alarm sound

//   useEffect(() => {
//     const checkReminders = async () => {
//       try {
//         const response = await fetch(
//           `http://127.0.0.1:8000/api/reminders/${userId}/`
//         );
//         const data = await response.json();

//         // Check if the reminder time exists and is valid
//         if (data.reminder_time) {
//           setShowPopup(true);
//           audio.play();  // Play the alarm sound when reminder popup is shown
//         }
//       } catch (error) {
//         console.error("Error fetching reminders:", error);
//       }
//     };

//     // Check for reminders every minute (60000ms)
//     const interval = setInterval(checkReminders, 60000);
//     return () => clearInterval(interval);
//   }, [userId, audio]);

//   return (
//     <>
//       {showPopup && (
//         <div className="fixed inset-0 flex items-center justify-center z-50">
//           <div className="bg-white p-6 rounded-2xl shadow-xl max-w-sm text-center border border-gray-300 animate__animated animate__fadeIn">
//             <h2 className="text-xl font-semibold text-gray-800">
//               Time to Track Your Mood!
//             </h2>
//             <p className="text-gray-600 mt-2">Stay consistent with your mood tracking.</p>
//             <button
//               className="mt-4 bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg flex items-center justify-center mx-auto"
//               onClick={() => setShowPopup(false)}
//             >
//               <AiOutlineClose className="mr-2" />
//               Close
//             </button>
//           </div>
//         </div>
//       )}
//     </>
//   );
// };

// export default ReminderPopup;


import React from 'react'

const ReminderPopup = () => {
  return (
    <>
    </>
    // <div>ReminderPopup</div>
  )
}

export default ReminderPopup
