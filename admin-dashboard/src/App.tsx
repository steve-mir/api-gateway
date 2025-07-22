import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Services } from './pages/Services'
import { Configuration } from './pages/Configuration'
import { Metrics } from './pages/Metrics'
import { Logs } from './pages/Logs'
import { Alerts } from './pages/Alerts'
import { Users } from './pages/Users'
import { ServiceTopology } from './pages/ServiceTopology'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/services" element={<Services />} />
        <Route path="/topology" element={<ServiceTopology />} />
        <Route path="/configuration" element={<Configuration />} />
        <Route path="/metrics" element={<Metrics />} />
        <Route path="/logs" element={<Logs />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/users" element={<Users />} />
      </Routes>
    </Layout>
  )
}

export default App