import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import { AuthProvider } from "./context/AuthContext";
import Login from "./pages/auth/Login";
import Register from "./pages/auth/Register";
import ForgotPassword from "./pages/auth/ForgotPassword";

import Home from "./pages/home/Home";
import MoodTrack from "./pages/mood/MoodTrack";
import AddJournal from "./pages/journal/AddJournal";
import ViewJournal from "./pages/journal/ViewJournal";
import AddPost from "./pages/Post/AddPost";
import ViewPost from "./pages/Post/ViewPost";
import EditPost from "./pages/Post/EditPost";
import EditJournal from "./pages/journal/EditJournal";
import PostList from "./pages/Post/PostList";
import ViewProfile from "./pages/profile/ViewProfile";
import ChangePassword from "./pages/profile/ChangePassword";
import Footer from "./pages/home/Footer";
import ChatWithAI from "./pages/chat/ChatWithAI";
import ViewReport from "./pages/mood/ViewReport";
import ReportSettings from "./pages/mood/ReportSettings";
import ReminderPopup from "./pages/home/ReminderPopup";

const App = () => {
  return (
    <Router>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<Home/>} />
          <Route path="/" element={<Footer/> } />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgotPassword" element={<ForgotPassword/>} />
          <Route path="/moodTrack" element={<MoodTrack/>} />
          <Route path="/viewReport/:id" element={<ViewReport/>} />
          <Route path="/reportSettings/:id" element={<ReportSettings/>} />
          <Route path="/journalTrack" element={<AddJournal/>} />
          <Route path="/viewJournal/:id" element={<ViewJournal/>} />
          <Route path="/editJournal/:id" element={<EditJournal/>} />

          <Route path="/addPost" element={<AddPost/>} />
          <Route path="/postList" element={<PostList/>} />
          <Route path="/viewPost/:id" element={<ViewPost/>} />
          <Route path="/editPost/:id" element={<EditPost/>} />

          <Route path="/profile" element={<ViewProfile/>} />
          <Route path="/changePassword" element={<ChangePassword/>} />

          <Route path="/chatWithAI" element={<ChatWithAI/>} />
          
          <Route path="/reminder" element={<ReminderPopup/>} />

        </Routes>
      </AuthProvider>
    </Router>
  );
};

export default App;
