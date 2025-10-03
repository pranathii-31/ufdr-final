import React, { useState } from "react";
import { login } from "../api/api";

const Login = ({ onLoginSuccess }) => {
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const email = e.target.email.value;
    const password = e.target.password.value;
    setLoading(true);

    try {
      const response = await login(email, password);
      console.log("Login successful:", response);
      onLoginSuccess(); // Call success callback to redirect or update UI
    } catch (error) {
      console.error("Login error:", error);
      alert("Login failed: " + (error.message || "Unknown error"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input name="email" type="email" placeholder="Email" required />
      <input name="password" type="password" placeholder="Password" required />
      <button type="submit" disabled={loading}>
        {loading ? "Logging in..." : "Log In"}
      </button>
    </form>
  );
};

export default Login;