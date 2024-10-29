import { useState } from 'react'
import './signup.css'
import { Button } from 'react-bootstrap'
import { Link } from 'react-router-dom'
import axios from 'axios'

function Signup() {

    const [username, setInputName] = useState('')
    const [email, setInputEmail] = useState('')
    const [password, setInputPassword] = useState('')
    const handleSubmit = async (e) => {
        e.preventDefault();
        console.log(username, email, password); 
        
        // Check if all required fields have values
        if (!username || !email || !password) {
          console.log("All fields are required.");
          return; // Stop the form submission if validation fails
        }
      
        try {
            const res = await axios.post('http://localhost:8080/submit', {
              username,
              email,
              password
            });
            console.log(res); // Log response if successful
        } catch (err) {
            console.log(err); // Log error if request fails
        }
    };
    
  return (
    
    
        <>
        <form className='addUser' onSubmit={handleSubmit}>
                <h2  style={{textAlign:'center', fontSize:'bold'}}>Sign Up</h2>
            <div className='inputgroup'>
                <label htmlFor='name'>Name:</label>
                <input type='text' id='name'  placeholder='Enter your name' onChange={(e)=>setInputName(e.target.value)}></input>

                <label htmlFor='name'>Email:</label>
                <input type='text' id='name'  placeholder='Enter Email address' onChange={(e)=>setInputEmail(e.target.value)}></input>

                <label htmlFor='name'>Password:</label>
                <input type='text' id='name'   placeholder='Enter password' className='mb-5' onChange={(e)=>setInputPassword(e.target.value)}></input>

                <Button className='mt-3 mb-3'   variant="success" type='submit'   >Sign up</Button>{' '}

                <div className='login mt-3'>
                    <p>Already have a account?</p>
                    <Link to='/login'>
                    <Button  className="btn-sm " variant="primary">Login</Button>{' '}
                    </Link>
                </div>
                </div>    

        </form>
        </>
  
  )
}

export default Signup