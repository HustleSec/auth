import React, { useEffect, useState } from "react";
import api from "./app";

export const Profile = () => {
  const [profile, setProfile] = useState<any>(null);

  const fetchProfile = async () => {
    try {
		await api.post("/api/user/login", {
			email: "brosx",
			name: "borz",
			password: "test"
		});
      const response = await api.get("/api/user/profile");
      setProfile(response.data);
    } catch (err) {
      console.error("Failed to fetch profile", err);
      setProfile(null);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  if (!profile) return <div>you need to login first</div>;

  return (
    <div>
      <h1>Profile</h1>
      <p>Username: {profile.user.UserInfo.username}</p>
      <p>Email: {profile.user.UserInfo.email}</p>
      <p>ID: {profile.user.UserInfo.id}</p>
      <p>Token issued at: {new Date(profile.user.iat * 1000).toLocaleString()}</p>
      <p>Token expires at: {new Date(profile.user.exp * 1000).toLocaleString()}</p>
    </div>
  );
};
