import Login from "./components/loginSingnup/Login";
import Signup from "./components/loginSingnup/Signup";

import { Route, Routes } from 'react-router-dom';
import Home from "./Home";


function App() {
  return (
    <Routes>
      <Route path="/" element={<Home/>} />
      <Route path="/home" element={<Home/>} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/login" element={<Login />} />
    </Routes>
  );
}

export default App;
