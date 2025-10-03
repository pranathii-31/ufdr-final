import React, { createContext, useState, useContext } from "react";

// Create the AuthContext
const AuthContext = createContext();

// AuthProvider component to wrap your app
export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null); // Store user info or token

  const login = (userData) => {
    setUser(userData); // Save user data (e.g., token or user info)
    localStorage.setItem("user", JSON.stringify(userData)); // Persist in localStorage
  };

  const logout = () => {
    setUser(null); // Clear user data
    localStorage.removeItem("user"); // Remove from localStorage
  };

  const isAuthenticated = !!user; // Check if user is logged in

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated }}>
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook to use AuthContext
export const useAuth = () => {
  return useContext(AuthContext);
};