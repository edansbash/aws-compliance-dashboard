import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Findings from './pages/Findings'
import FindingDetail from './pages/FindingDetail'
import Scans from './pages/Scans'
import Rules from './pages/Rules'
import RuleFindings from './pages/RuleFindings'
import CompliancePacks from './pages/CompliancePacks'
import CompliancePackDetail from './pages/CompliancePackDetail'
import Exceptions from './pages/Exceptions'
import Accounts from './pages/Accounts'
import AuditLogs from './pages/AuditLogs'
import Remediation from './pages/Remediation'
import Settings from './pages/Settings'
import Reports from './pages/Reports'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/findings/:id" element={<FindingDetail />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/rules" element={<Rules />} />
        <Route path="/rules/:id/findings" element={<RuleFindings />} />
        <Route path="/compliance-packs" element={<CompliancePacks />} />
        <Route path="/compliance-packs/:id" element={<CompliancePackDetail />} />
        <Route path="/exceptions" element={<Exceptions />} />
        <Route path="/accounts" element={<Accounts />} />
        <Route path="/audit-logs" element={<AuditLogs />} />
        <Route path="/remediation" element={<Remediation />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/reports" element={<Reports />} />
      </Routes>
    </Layout>
  )
}

export default App
