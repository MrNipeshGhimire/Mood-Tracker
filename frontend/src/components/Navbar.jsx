import { useState, useContext, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import AuthContext from "../context/AuthContext";
import axios from "axios";
import { Bell } from "lucide-react";
import ConfirmPopup from "../context/Confirmpopup";

function Navbar() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const [isNotificationOpen, setIsNotificationOpen] = useState(false); // State for notification dropdown
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0); // Track unread notifications count
  const { user, logout, loading } = useContext(AuthContext);
  const [showConfirm, setShowConfirm] = useState(false);
  const navigate = useNavigate();

  const confirmLogout = () => {
    logout();  // Call your logout function here
    setShowConfirm(false);
  };
  
  const cancelLogout = () => {
    setShowConfirm(false);
  };

  const toggleMenu = () => {
    setIsMenuOpen(!isMenuOpen);      
  };

  const toggleDropdown = () => {
    setIsDropdownOpen(!isDropdownOpen);
    setIsNotificationOpen(false); // Close notifications dropdown when user menu is open
  };

  const toggleNotification = () => {
    setIsNotificationOpen(!isNotificationOpen);
    setIsDropdownOpen(false); // Close user menu dropdown when notification is open
  };

  const handleLogout = () => {
    setShowConfirm(true);
    // if (confirmLogout) {
    //   logout();
    // }
  };

  useEffect(() => {
    if (user) {
      fetchNotifications();
    }
  }, [user]);

  const fetchNotifications = async () => {
    try {
      const response = await axios.get(`http://127.0.0.1:8000/api/notifications/${user.id}/`);
      setNotifications(response.data.notifications);
     console.log(response.data.unread_count+"hello")
      setUnreadCount(response.data.unread_count);
    } catch (error) {
      console.error("Error fetching notifications", error);
    }
  };

  const markNotificationAsRead = async (notificationId) => {
    try {
      await axios.post(`http://127.0.0.1:8000/api/notifications/read/${notificationId}/${user.id}/`);
      setNotifications((prev) => prev.filter((n) => n.id !== notificationId));
      setUnreadCount((prev) => prev - 1); // Decrease the unread count when a notification is read
      navigate("/postList");
    } catch (error) {
      console.error("Error marking notification as read", error);
    }
  };

  if (loading) {
    return null; // Show nothing while loading
  }

  return (
    <header className="bg-white shadow-lg py-4 sticky top-0 z-50">
      <div className="container mx-auto flex items-center justify-between px-4">
        {/* Logo */}
        <Link to="/" className="flex items-center text-primary hover:text-secondary">
          <span className="text-2xl font-bold text-primaryBg">
            Mood<span className="text-blue-700">Net.</span>
          </span>
        </Link>

        {/* Mobile menu button */}
        <div className="md:hidden">
          <button onClick={toggleMenu} className="text-gray-800 hover:text-primary">
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16m-7 6h7" />
            </svg>
          </button>
        </div>

        {/* Desktop Navigation */}
        <nav className="hidden md:block">
          <ul className="flex space-x-8">
            <li><Link to="/" className="font-bold hover:text-primary">Home</Link></li>
            <li><Link to="/postList" className="hover:text-primary">Public Post</Link></li>
            <li><Link to="/moodTrack" className="hover:text-primary">Tracker</Link></li>
            <li><Link to="/journalTrack" className="hover:text-primary">Add Journal</Link></li>
            <li><Link to="/chatWithAI" className="hover:text-primary">Chat With AI</Link></li>

            {user && (
              <>
                {/* Notifications Bell */}
                <li className="relative">
                  <button onClick={toggleNotification} className="relative text-gray-800">
                    <Bell className="h-6 w-6" />
                    {unreadCount > 0 && (
                      <span className="absolute -top-2 -right-2 bg-red-600 z-50 text-white text-xs px-2 py-0.5 rounded-full">
                        {unreadCount}
                      </span>
                    )}
                  </button>
                
                  {/* Notifications Dropdown */}
                  {isNotificationOpen && (
                    <ul className="absolute right-0 mt-2 w-48 bg-white shadow-lg rounded-lg overflow-hidden border">
                      {notifications.length > 0 ? (
                        notifications.map((notification) => (
                          <button
                            key={notification.id}
                            onClick={() => markNotificationAsRead(notification.id)}
                            className="block w-full text-left px-4 py-2 hover:bg-gray-200"
                          >
                            {notification.message}
                          </button>
                        ))
                      ) : (
                        <p className="text-center px-4 py-2">No new notifications</p>
                      )}
                    </ul>
                  )}
                </li>

                {/* User Profile Dropdown */}
                <li className="relative">
                  <button
                    onClick={toggleDropdown}
                    className="flex items-center space-x-2 font-bold hover:text-primary focus:outline-none"
                  >
                    <span className="w-8 h-8 flex items-center justify-center rounded-full bg-primaryBg text-white font-semibold">
                      {user.username.charAt(0).toUpperCase()}
                    </span>
                    <span>{user.username}</span>
                    {/* Down Arrow Icon */}
                    <svg
                      className="h-4 w-4 transition-transform duration-200"
                      style={{ transform: isDropdownOpen ? "rotate(180deg)" : "rotate(0)" }}
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      viewBox="0 0 24 24"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                    </svg>
                  </button>
                  {isDropdownOpen && (
                    <ul className="absolute right-0 mt-2 w-48 bg-white shadow-lg rounded-lg overflow-hidden border">
                      <li><Link to="/profile" className="block px-4 py-2 hover:bg-gray-200">View Profile</Link></li>
                      <li><Link to="/changePassword" className="block px-4 py-2 hover:bg-gray-200">Change Password</Link></li>
                      <li><Link to={`/reportSettings/${user.id}`} className="block px-4 py-2 hover:bg-gray-200">Settings</Link></li>
                      <li>
                        <button
                          onClick={handleLogout}
                          className="block w-full text-left px-4 py-2 text-red-500 hover:bg-gray-200"
                        >
                          Logout
                        </button>
                      </li>
                    </ul>
                  )}
                </li>
              </>
            )}
            {!user && (
              <li>
                <Link to="/login" className="bg-primaryBg hover:bg-secondary text-white px-4 py-2 rounded-md">
                  Login
                </Link>
              </li>
            )}
          </ul>
        </nav>

        {/* Mobile Navigation */}
        <nav className={`absolute top-16 left-0 w-full bg-white shadow-lg transition-all duration-300 ${isMenuOpen ? 'block' : 'hidden'}`}>
          <ul className="flex flex-col space-y-4 px-4 py-4">
            <li><Link to="/" className="hover:text-primary">Home</Link></li>
            <li><Link to="/postList" className="hover:text-primary">Public Post</Link></li>
            <li><Link to="/moodTrack" className="hover:text-primary">Tracker</Link></li>
            <li><Link to="/journalTrack" className="hover:text-primary">Add Journal</Link></li>
            <li><Link to="/chatWithAI" className="hover:text-primary">Chat With AI</Link></li>

            {user ? (
              <>
                <li>
                  <button onClick={toggleDropdown} className="w-full text-left flex items-center space-x-2 font-bold hover:text-primary">
                    <span className="w-8 h-8 flex items-center justify-center rounded-full bg-primaryBg text-white font-semibold">
                      {user.username.charAt(0).toUpperCase()}
                    </span>
                    <span>{user.username}</span>
                  </button>

                  {isDropdownOpen && (
                    <ul className="bg-gray-100 rounded-md shadow-md mt-2">
                      <li><Link to="/profile" className="block px-4 py-2 hover:bg-gray-200">View Profile</Link></li>
                      <li><Link to="/changePassword" className="block px-4 py-2 hover:bg-gray-200">Change Password</Link></li>
                      <li><Link to={`/reportSettings/${user.id}`} className="block px-4 py-2 hover:bg-gray-200">Settings</Link></li>
                      <li>
                        <button
                          onClick={handleLogout}
                          className="block w-full text-left px-4 py-2 text-red-500 hover:bg-gray-200"
                        >
                          Logout
                        </button>
                      </li>
                    </ul>
                  )}
                </li>
              </>
            ) : (
              <li>
                <Link to="/login" className="bg-primaryBg hover:bg-secondary text-white px-4 py-2 rounded-md">
                  Login
                </Link>
              </li>
            )}
          </ul>
        </nav>
      </div>
      {showConfirm && (
  <ConfirmPopup
    message="Are you sure you want to logout?"
    onConfirm={confirmLogout}
    onCancel={cancelLogout}
  />
)}
    </header>
    
  );
}

export default Navbar;




