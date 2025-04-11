import { Link } from "react-router-dom";
import { FaFacebook, FaTwitter, FaInstagram, FaLinkedin } from "react-icons/fa";

function Footer() {
  return (
    <footer className="bg-primaryBg text-white py-10">
      <div className="container mx-auto px-4 flex flex-col md:flex-row justify-between items-center">
        {/* Logo and Branding */}
        <div className="mb-6 md:mb-0 text-center md:text-left">
          <h2 className="text-3xl font-bold">Mood Tracker</h2>
          <p className="text-lg">Track your emotions, stay mindful.</p>
        </div>

        {/* Navigation Links */}
        <nav className="mb-6 md:mb-0">
          <ul className="flex flex-wrap justify-center md:justify-start space-x-8 text-lg">
            <li><Link to="/" className="hover:text-gray-300">Home</Link></li>
            <li><Link to="/postList" className="hover:text-gray-300">Public Post</Link></li>
            <li><Link to="/moodTrack" className="hover:text-gray-300">Tracker</Link></li>
            <li><Link to="/journalTrack" className="hover:text-gray-300">Add Journal</Link></li>
            <li><Link to="/chatWithAI" className="hover:text-gray-300">Chat With AI</Link></li>
          </ul>
        </nav>

        {/* Social Media Links */}
        <div className="flex space-x-6">
          <a href="#" className="hover:text-gray-300 transition">
            <FaFacebook size={24} />
          </a>
          <a href="#" className="hover:text-gray-300 transition">
            <FaTwitter size={24} />
          </a>
          <a href="#" className="hover:text-gray-300 transition">
            <FaInstagram size={24} />
          </a>
          <a href="#" className="hover:text-gray-300 transition">
            <FaLinkedin size={24} />
          </a>
        </div>
      </div>

      {/* Copyright Section */}
      <div className="text-center text-lg mt-6 border-t border-gray-500 pt-4">
        &copy; {new Date().getFullYear()} Mood Tracker. All rights reserved.
      </div>
    </footer>
  );
}

export default Footer;



