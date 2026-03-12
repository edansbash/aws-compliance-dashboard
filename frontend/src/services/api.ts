import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Health
export const getHealth = () => api.get('/health')

// Search
export const search = (q: string, type = 'findings') =>
  api.get('/search', { params: { q, type } })

// Accounts
export const getAccounts = (page = 1, perPage = 20) =>
  api.get('/accounts', { params: { page, per_page: perPage } })

export const createAccount = (data: {
  account_id: string
  name: string
  role_arn?: string
  external_id?: string
}) => api.post('/accounts', data)

export const updateAccount = (id: string, data: Partial<{
  name: string
  role_arn: string
  external_id: string
  is_active: boolean
}>) => api.put(`/accounts/${id}`, data)

export const deleteAccount = (id: string) => api.delete(`/accounts/${id}`)

export const testAccountConnection = (id: string) => api.post(`/accounts/${id}/test`)

// Scans
export const getScans = (page = 1, perPage = 20) =>
  api.get('/scans', { params: { page, per_page: perPage } })

export const getScan = (id: string) => api.get(`/scans/${id}`)

export const createScan = (data: {
  account_ids?: string[]
  regions?: string[]
  rule_ids?: string[]
}) => api.post('/scans', data)

export const getScanFindings = (id: string, page = 1, perPage = 20) =>
  api.get(`/scans/${id}/findings`, { params: { page, per_page: perPage } })

export const cancelScan = (id: string) => api.post(`/scans/${id}/cancel`)

// Findings
export const getFindings = (params: {
  status?: string
  workflow_status?: string
  severity?: string
  account_id?: string
  region?: string
  rule_id?: string
  page?: number
  per_page?: number
}) => api.get('/findings', { params })

export const getFinding = (id: string) => api.get(`/findings/${id}`)

export const updateFindingWorkflow = (id: string, data: {
  workflow_status: string
  notes?: string
  updated_by?: string
}) => api.patch(`/findings/${id}/workflow`, data)

export const rescanFinding = (id: string) => api.post(`/findings/${id}/rescan`)

export const createJiraTicketForFinding = (id: string) => api.post(`/findings/${id}/create-jira-ticket`)

export const getFindingsSummary = (params?: {
  account_id?: string
  region?: string
}) => api.get('/findings/summary', { params })

// Rules
export const getRules = (page = 1, perPage = 50) =>
  api.get('/rules', { params: { page, per_page: perPage } })

export const getRule = (id: string) => api.get(`/rules/${id}`)

export const updateRule = (id: string, data: { is_enabled: boolean }) =>
  api.put(`/rules/${id}`, data)

export const scanRule = (id: string) => api.post(`/rules/${id}/scan`)

export const remediateAllRule = (id: string) => api.post(`/rules/${id}/remediate-all`)

// Exceptions
export const getExceptions = (params?: {
  scope?: string
  rule_id?: string
  account_id?: string
  page?: number
  per_page?: number
}) => api.get('/exceptions', { params })

export const createException = (data: {
  rule_id: string
  finding_id?: string
  resource_id?: string
  account_id?: string
  scope: string
  justification: string
  created_by: string
  expires_at?: string
}) => api.post('/exceptions', data)

export const createBulkExceptions = (data: {
  finding_ids: string[]
  justification: string
  created_by: string
  expires_at?: string
}) => api.post('/exceptions/bulk', data)

export const updateException = (id: string, data: {
  justification?: string
  expires_at?: string | null
}) => api.patch(`/exceptions/${id}`, data)

export const bulkUpdateExceptions = (data: {
  exception_ids: string[]
  justification?: string
  expires_at?: string | null
}) => api.patch('/exceptions/bulk/update', data)

export const deleteException = (id: string) => api.delete(`/exceptions/${id}`)

// Remediation
export const getAvailableRemediations = () => api.get('/remediation-jobs/available')

export const getRemediationJobs = (params?: {
  page?: number
  per_page?: number
}) => api.get('/remediation-jobs', { params })

export const createRemediationJob = (data: {
  finding_ids: string[]
  confirmed_by: string
}) => api.post('/remediation-jobs', data)

export const previewRemediation = (data: {
  finding_ids: string[]
}) => api.post('/remediation-jobs/preview', data)

export const getRemediationJob = (id: string) => api.get(`/remediation-jobs/${id}`)

export const cancelRemediationJob = (id: string) =>
  api.post(`/remediation-jobs/${id}/cancel`)

export const getRemediationLogs = (id: string, after?: string) =>
  api.get(`/remediation-jobs/${id}/logs`, { params: after ? { after } : undefined })

// Audit Logs
export const getAuditLogs = (params?: {
  action?: string
  user?: string
  resource_id?: string
  account_id?: string
  start_date?: string
  end_date?: string
  page?: number
  per_page?: number
}) => api.get('/audit-logs', { params })

export const getAuditLog = (id: string) => api.get(`/audit-logs/${id}`)

export const exportAuditLogsCsv = (params?: {
  action?: string
  user?: string
  resource_id?: string
  start_date?: string
  end_date?: string
}) => api.get('/audit-logs/export', { params, responseType: 'blob' })

// Config
export const getRegions = () => api.get('/config/regions')

export const updateRegions = (regions: string[]) =>
  api.put('/config/regions', { regions })

// Compliance Packs
export const getCompliancePacks = (page = 1, perPage = 20) =>
  api.get('/compliance-packs', { params: { page, per_page: perPage } })

export const getCompliancePack = (id: string) => api.get(`/compliance-packs/${id}`)

export const createCompliancePack = (data: {
  name: string
  description?: string
  rule_ids?: string[]
}) => api.post('/compliance-packs', data)

export const updateCompliancePack = (id: string, data: {
  name?: string
  description?: string
  is_enabled?: boolean
}) => api.patch(`/compliance-packs/${id}`, data)

export const updateCompliancePackRules = (id: string, ruleIds: string[]) =>
  api.put(`/compliance-packs/${id}/rules`, { rule_ids: ruleIds })

export const addRuleToCompliancePack = (packId: string, ruleId: string) =>
  api.post(`/compliance-packs/${packId}/rules/${ruleId}`)

export const removeRuleFromCompliancePack = (packId: string, ruleId: string) =>
  api.delete(`/compliance-packs/${packId}/rules/${ruleId}`)

export const deleteCompliancePack = (id: string) => api.delete(`/compliance-packs/${id}`)

// Notifications
export const getSlackConfig = () => api.get('/notifications/slack')

export const updateSlackConfig = (data: {
  webhook_url?: string
  is_enabled?: boolean
  min_severity?: string
  notify_on_new_findings?: boolean
  notify_on_regression?: boolean
  notify_on_scan_complete?: boolean
}) => api.put('/notifications/slack', data)

export const testSlackNotification = () => api.post('/notifications/slack/test')

// JIRA Notifications
export const getJiraConfig = () => api.get('/notifications/jira')

export const updateJiraConfig = (data: {
  base_url?: string
  email?: string
  api_token?: string
  project_key?: string
  issue_type?: string
  is_enabled?: boolean
  min_severity?: string
  notify_on_new_findings?: boolean
  notify_on_regression?: boolean
}) => api.put('/notifications/jira', data)

export const testJiraConnection = () => api.post('/notifications/jira/test')

// Scheduled Scans
export const getScheduledScans = (page = 1, perPage = 20) =>
  api.get('/schedules', { params: { page, per_page: perPage } })

export const getScheduledScan = (id: string) => api.get(`/schedules/${id}`)

export const createScheduledScan = (data: {
  name: string
  description?: string
  account_ids?: string[]
  regions?: string[]
  rule_ids?: string[]
  schedule_type: 'cron' | 'interval'
  schedule_expression: string
  timezone?: string
  enabled?: boolean
}) => api.post('/schedules', data)

export const updateScheduledScan = (id: string, data: Partial<{
  name: string
  description: string
  account_ids: string[]
  regions: string[]
  rule_ids: string[]
  schedule_type: 'cron' | 'interval'
  schedule_expression: string
  timezone: string
  enabled: boolean
}>) => api.put(`/schedules/${id}`, data)

export const deleteScheduledScan = (id: string) => api.delete(`/schedules/${id}`)

export const runScheduledScan = (id: string) => api.post(`/schedules/${id}/run`)

export const enableScheduledScan = (id: string) => api.post(`/schedules/${id}/enable`)

export const disableScheduledScan = (id: string) => api.post(`/schedules/${id}/disable`)

export const getSchedulerStatus = () => api.get('/schedules/status')

// Reports
export const getReports = (page = 1, perPage = 20) =>
  api.get('/reports', { params: { page, per_page: perPage } })

export const getReport = (id: string) => api.get(`/reports/${id}`)

export const createReport = (data: {
  report_type: 'DASHBOARD_PDF' | 'FINDINGS_EXCEL'
  scan_id?: string
  filters?: {
    account_ids?: string[]
    regions?: string[]
    severities?: string[]
    statuses?: string[]
  }
}) => api.post('/reports', data)

export const downloadReport = (id: string) =>
  api.get(`/reports/${id}/download`, { responseType: 'blob' })

export const deleteReport = (id: string) => api.delete(`/reports/${id}`)

export const generateDashboardPdf = (params?: {
  scan_id?: string
  account_ids?: string
  regions?: string
  severities?: string
}) => api.post('/reports/generate/dashboard-pdf', null, { params, responseType: 'blob' })

export const generateFindingsExcel = (params?: {
  scan_id?: string
  account_ids?: string
  regions?: string
  severities?: string
  statuses?: string
}) => api.post('/reports/generate/findings-excel', null, { params, responseType: 'blob' })
