import React, { useState } from "react";
import { signup } from "../api/api";

const Signup = ({ onSignupSuccess }) => {
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const name = e.target.name.value;
    const email = e.target.email.value;
    const password = e.target.password.value;
    setLoading(true);
    
    try {
      const response = await signup(name, email, password);
      console.log("Signup successful:", response);
      onSignupSuccess(); // Call success callback to redirect to login
    } catch (error) {
      console.error("Signup error:", error);
      alert("Signup failed: " + (error.message || "Unknown error"));
    } finally {
      setLoading(false);
    }
  };


  return (
    <form onSubmit={handleSubmit}>
      <input name="name" type="text" placeholder="Name" required />
      <input name="email" type="email" placeholder="Email" required />
      <input name="password" type="password" placeholder="Password" required />
      <button type="submit" disabled={loading}>
        {loading ? "Signing up..." : "Sign Up"}
      </button>
    </form>
  );
};

export default Signup;
