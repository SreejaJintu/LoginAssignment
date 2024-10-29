import axios from 'axios';
import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

function Home() {
  axios.defaults.withCredentials = true;
  const navigate = useNavigate();

  useEffect(() => {
    axios.get('http://localhost:8080/home')
      .then(res => {
        if (res.data !== "Success") {
          navigate('/login');
        }
        console.log(res);
      })
      .catch(err => console.log(err));
  }, [navigate]);

  return (
    <div><h1>Home</h1></div>
  );
}

export default Home;
