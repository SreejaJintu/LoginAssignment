import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Button from 'react-bootstrap/Button';
import './login.css';
import axios from 'axios';
import { Link } from 'react-router-dom';

function Login() {

  const [username, setInputUsername] = useState('');
  const [password, setInputPassword] = useState('');

  const navigate = useNavigate();

  axios.defaults.withCredentials=true;
  const handleSubmit = async (e) => {
    e.preventDefault();
    console.log(username, password);

    // Proceed only if fields are populated
    if (!username || !password) {
      console.log("All fields are required.");
      return;
    }

    try {
      const res = await axios.post('http://localhost:8080/login', { username, password });
      console.log(res);
      navigate('/home'); // Navigate only on successful response
    } catch (err) {
      console.log(err); // Log error if request fails
    }
  };

  return (
    <div>
      <form className='addUser' onSubmit={handleSubmit}>
        <h2 style={{ textAlign: 'center', fontWeight: 'bold' }}>Login</h2>
        <div className='inputgroup'>
          <label htmlFor='email'>Username:</label>
          <input
            type='text'
            id='name'
            placeholder='Enter your username'
            value={username}
            onChange={(e) => setInputUsername(e.target.value)}
          />

          <label htmlFor='password'>Password:</label>
          <input
            type='password'
            id='password'
            placeholder='Enter password'
            value={password}
            onChange={(e) => setInputPassword(e.target.value)}
          />
          <Button className='mt-3 mb-3' variant="success" type='submit'>Login</Button>

          <div className='login'>
            <p>Don't have an account?</p>
            <Link to='/signup'>
              <Button className="btn-sm" variant="primary">Sign up</Button>
            </Link>
          </div>
        </div>    
      </form>
    </div>
  );
}

export default Login;
