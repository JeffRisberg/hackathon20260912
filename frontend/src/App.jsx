import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Home from './pages/Home'
import SecWeave from './pages/SecWeave'
import './App.css'

function App() {
  return (
    <BrowserRouter>
      <nav className="navbar">
        <NavLink to="/" end>
          Home
        </NavLink>
        <NavLink to="/secweave">SecWeave</NavLink>
      </nav>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/secweave" element={<SecWeave />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
