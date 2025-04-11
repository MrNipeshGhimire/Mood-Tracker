import React, { useState, useEffect, useContext } from "react";
import Navbar from "../../components/Navbar";
import axios from "axios";
import AuthContext from "../../context/AuthContext";
import { useNavigate, useParams } from "react-router-dom";
import { FaDownload } from "react-icons/fa";

const ViewReport = () => {
  const { id } = useParams(); // User ID from URL
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [reportStatus, setReportStatus] = useState(null); // Store the report status
console.log(reportStatus)
  const { user, isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();

  // Redirect if not logged in
  if (!isAuthenticated) {
    navigate("/login");
  }

  // Fetch the report status when the component mounts
  useEffect(() => {
    const fetchReportStatus = async () => {
      try {
        const response = await axios.get(`http://127.0.0.1:8000/api/report-status/${id}/`);
        setReportStatus(response.data.status); // Assuming the response has a 'status' field
        setLoading(false);
      } catch (err) {
        setError("You have not set the report generating time.");
        setLoading(false);
      }
    };

    fetchReportStatus();
  }, [id]);

  const handleDownloadReport = () => {
    // Generate the PDF report
    window.open(`http://127.0.0.1:8000/api/generate-report/${id}/`, "_blank");
  };

  // Handle loading state
  if (loading) return <div className="text-center mt-10">Loading...</div>;

  // Handle error state
  if (error) return <div className="text-red-500 text-center mt-10">{error}</div>;

  return (
    <>
      <Navbar />
      <div className="flex flex-col items-center py-8 bg-gray-100 min-h-screen">
        <h1 className="text-3xl font-semibold mb-6 text-center">Mood Report</h1>
        {reportStatus === "pending" ? (
          <div className="w-full max-w-2xl p-6 bg-white shadow-lg rounded-lg">
            <h2 className="text-xl font-semibold text-gray-700 mb-4">No Report Generated</h2>
            <p>The report is still being generated. Please try again later.</p>
          </div>
        ) : reportStatus === "ready" ? (
          <div className="w-full max-w-2xl p-6 bg-white shadow-lg rounded-lg">
            <h2 className="text-xl font-semibold text-gray-700 mb-4">User Details</h2>
            <p><strong>User ID:</strong> {user.id}</p>
            <p><strong>Name:</strong> {user.first_name} {user.last_name}</p>
            <p><strong>Email:</strong> {user.email}</p>

            <button
              onClick={handleDownloadReport}
              className="mt-6 px-6 py-2 bg-blue-600 text-white rounded-lg flex items-center justify-center hover:bg-blue-700 transition duration-300"
            >
              <FaDownload className="mr-2" /> Download Report
            </button>
          </div>
        ) : (
          <div className="w-full max-w-2xl p-6 bg-white shadow-lg rounded-lg">
            <h2 className="text-xl font-semibold text-gray-700 mb-4">No Report Available</h2>
            <p>There was an issue generating the report. Please try again later.</p>
          </div>
        )}
      </div>
    </>
  );
};

export default ViewReport;
