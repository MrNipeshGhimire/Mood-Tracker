import React, { useState, useEffect } from "react";
import axios from "axios";
import { useParams, useNavigate } from "react-router-dom";
import Navbar from "../../components/Navbar";
import { FaClock } from "react-icons/fa";

const ReportSettings = () => {
  const { id } = useParams(); // Get the user ID from the URL
  const navigate = useNavigate();
  const [settings, setSettings] = useState({
    report_generate_time: "", // Default empty value
  });
  const [error, setError] = useState(null);

  // Fetch the current settings for the user
  useEffect(() => {
  
  }, []);

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      // Send the updated settings to the backend
      await axios.post(`http://127.0.0.1:8000/api/report-settings/${id}/`, {
        report_time_offset: (new Date(settings.report_generate_time) - new Date()) / (1000 * 60), // in minutes
      });

      alert("Report settings updated successfully!");
      navigate("/"); // Navigate to the report page or wherever
    } catch (err) {
      setError("Failed to update report settings.");
    }
  };


  if (error) return <div>{error}</div>;

  return (
    <>
      <Navbar />
      <div className="flex flex-col items-center py-8 bg-gray-100 min-h-screen">
        <h1 className="text-3xl font-semibold mb-6 text-center">Set Report Alarm</h1>
        <div className="w-full max-w-2xl p-6 bg-white shadow-lg rounded-lg">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Section for Alarm Clock UI */}
            <div className="flex flex-col items-center">
              <FaClock className="text-blue-600 text-6xl mb-4" />
              <label
                htmlFor="report_generate_time"
                className="text-xl font-medium text-gray-700"
              >
                Set Report Generation Time (Alarm)
              </label>
              <input
                type="datetime-local"
                id="report_generate_time"
                name="report_generate_time"
                value={settings.report_generate_time}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    report_generate_time: e.target.value,
                  })
                }
                className="mt-4 px-4 py-2 border rounded-md w-80 md:w-full"
                min={new Date().toISOString().slice(0, 16)} // Ensure user can't set a time before the current time
              />
            </div>

            {/* Alarm Confirmation and Button */}
            <div className="flex justify-between items-center mt-6">
              <button
                type="submit"
                className="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition duration-300"
              >
                Set Alarm for Report
              </button>
            </div>

            {/* Countdown Timer */}
            <div className="mt-4 text-center text-gray-600">
              <p className="text-lg">Next Report Time:</p>
              <p className="font-semibold text-xl">{settings.report_generate_time ? new Date(settings.report_generate_time).toLocaleString() : "Not set"}</p>
            </div>
          </form>
        </div>
      </div>
    </>
  );
};

export default ReportSettings;
