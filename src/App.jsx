import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import InputTodo from './pages/input'
import './App.css'
import { BrowserRouter, Route, Routes } from 'react-router-dom'

function App() {
  const [count, setCount] = useState(0)

  return (
 <BrowserRouter>
 <Routes>
  <Route path='/' element={<InputTodo/>}/>
 </Routes>
 </BrowserRouter>
  )
}

export default App
