import { createContext, useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import PopupMessage from "./PopupMessage";

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [tokens, setTokens] = useState(null);
  const [loading, setLoading] = useState(true);
  const [popup, setPopup] = useState(null); // 💡 Popup state
  

  // ✅ Load user & tokens from localStorage on app start
  useEffect(() => {
    const storedTokens = localStorage.getItem("authTokens");
    const storedUser = localStorage.getItem("user");

    if (storedTokens) {
      setTokens(JSON.parse(storedTokens));
    }
    if (storedUser) {
      setUser(JSON.parse(storedUser));
    }

    if (storedTokens) {
      refreshToken();
    } else {
      setLoading(false);
    }
  }, []);

  // ✅ Ensure localStorage updates when user state changes
  useEffect(() => {
    if (user) {
      localStorage.setItem("user", JSON.stringify(user));
    }
  }, [user]);

  //showPopup
  const showPopup = (message) => {
    setPopup(message);
    setTimeout(() => setPopup(null), 3000); // hide after 3s
  };

  // ✅ LOGIN FUNCTION
  const login = async (formData) => {
    try {
      const response = await axios.post("http://127.0.0.1:8000/api/auth/login/", formData);
      const { access, refresh, user } = response.data;

      setTokens({ access, refresh });
      setUser(user);

      localStorage.setItem("authTokens", JSON.stringify({ access, refresh }));
      localStorage.setItem("user", JSON.stringify(user));

      navigate("/");
      showPopup("Login Successful! ✅");
    } catch (error) {
      console.error("Login failed", error.response?.data);
      showPopup("Login Failed ❌");
    }
  };

  // ✅ REGISTER FUNCTION
  const register = async (formData) => {
    try {
      await axios.post("http://127.0.0.1:8000/api/auth/register/", formData);
      showPopup("Registration Successful! Please log in.");
      navigate("/login");
    } catch (error) {
      console.error("Registration failed", error.response?.data);
      showPopup("Registration Failed!");
    }
  };

  // ✅ LOGOUT FUNCTION (Updated)
const logout = async () => {
  try {
    await axios.post("http://127.0.0.1:8000/api/auth/logout/");
  } catch (error) {
    console.error("Logout failed", error.response?.data);
  }

  // Clear local storage & state
  setTokens(null);
  setUser(null);
  localStorage.removeItem("authTokens");
  localStorage.removeItem("user");

  navigate("/");
};

  // ✅ TOKEN REFRESH FUNCTION
  const refreshToken = async () => {
    if (!tokens?.refresh) {
      logout();
      return;
    }

    try {
      const response = await axios.post("http://127.0.0.1:8000/api/auth/token/refresh/", {
        refresh: tokens.refresh,
      });

      const newTokens = { ...tokens, access: response.data.access };
      setTokens(newTokens);
      localStorage.setItem("authTokens", JSON.stringify(newTokens));

      setLoading(false);
    } catch (error) {
      console.error("Token refresh failed", error.response?.data);
      logout();
    }
  };

  return (
    <AuthContext.Provider value={{ user, login, register, logout, isAuthenticated: !!user }}>
    {!loading && children}
    {popup && <PopupMessage message={popup} onClose={() => setPopup(null)} />}
  </AuthContext.Provider>
  );
};

export default AuthContext;
