import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plug, Bell, Send, CheckCircle, XCircle, Loader2, Ticket, FileCode2, Github, RefreshCw, ChevronDown, Power } from 'lucide-react'
import { getSlackConfig, updateSlackConfig, testSlackNotification, getJiraConfig, testJiraConnection, getIaCConfig, triggerIaCSync, getIntegrations, updateIntegration } from '../services/api'
import { clsx } from 'clsx'

const severityOptions = [
  { value: 'CRITICAL', label: 'Critical only', color: 'text-red-600' },
  { value: 'HIGH', label: 'High and above', color: 'text-orange-600' },
  { value: 'MEDIUM', label: 'Medium and above', color: 'text-yellow-600' },
  { value: 'LOW', label: 'Low and above', color: 'text-blue-600' },
  { value: 'INFO', label: 'All severities', color: 'text-gray-600' },
]

// Collapsible help section component
function HelpSection({ title, children }: { title: string; children: React.ReactNode }) {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <div className="mt-6 bg-blue-50 rounded-lg">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-4 py-3 flex items-center justify-between text-left"
      >
        <span className="font-medium text-blue-900">{title}</span>
        <ChevronDown
          className={clsx(
            'w-5 h-5 text-blue-700 transition-transform duration-200',
            isOpen && 'rotate-180'
          )}
        />
      </button>
      {isOpen && (
        <div className="px-4 pb-4">
          {children}
        </div>
      )}
    </div>
  )
}


export default function Settings() {
  const queryClient = useQueryClient()

  // Slack state (UI-configurable options only)
  const [isEnabled, setIsEnabled] = useState(false)
  const [minSeverity, setMinSeverity] = useState('CRITICAL')
  const [notifyOnNew, setNotifyOnNew] = useState(true)
  const [notifyOnRegression, setNotifyOnRegression] = useState(true)
  const [notifyOnScanComplete, setNotifyOnScanComplete] = useState(true)
  const [hasChanges, setHasChanges] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)

  // JIRA state
  const [jiraTestResult, setJiraTestResult] = useState<{ success: boolean; message: string } | null>(null)

  // IaC state
  const [iacSyncResult, setIacSyncResult] = useState<{ success: boolean; message: string } | null>(null)

  const { data: config, isLoading } = useQuery({
    queryKey: ['slack-config'],
    queryFn: () => getSlackConfig(),
  })

  const { data: jiraConfig, isLoading: isLoadingJira } = useQuery({
    queryKey: ['jira-config'],
    queryFn: () => getJiraConfig(),
  })

  const { data: iacConfig, isLoading: isLoadingIac } = useQuery({
    queryKey: ['iac-config'],
    queryFn: () => getIaCConfig(),
  })

  const { data: integrations, isLoading: isLoadingIntegrations } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => getIntegrations(),
  })

  // Integration toggle mutation
  const integrationMutation = useMutation({
    mutationFn: ({ type, isEnabled }: { type: string; isEnabled: boolean }) =>
      updateIntegration(type, { is_enabled: isEnabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
    },
  })

  // Helper to get integration status
  const getIntegrationEnabled = (type: string): boolean => {
    const integration = integrations?.data?.integrations?.find(
      (i: { integration_type: string }) => i.integration_type === type
    )
    return integration?.is_enabled ?? true
  }

  // Sync Slack form state when config data loads
  useEffect(() => {
    if (config?.data) {
      setIsEnabled(config.data.is_enabled)
      setMinSeverity(config.data.min_severity)
      setNotifyOnNew(config.data.notify_on_new_findings)
      setNotifyOnRegression(config.data.notify_on_regression)
      setNotifyOnScanComplete(config.data.notify_on_scan_complete)
    }
  }, [config])

  const updateMutation = useMutation({
    mutationFn: updateSlackConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['slack-config'] })
      setHasChanges(false)
    },
  })

  const testMutation = useMutation({
    mutationFn: testSlackNotification,
    onSuccess: () => {
      setTestResult({ success: true, message: 'Test notification sent successfully!' })
      setTimeout(() => setTestResult(null), 5000)
    },
    onError: (error: any) => {
      setTestResult({
        success: false,
        message: error.response?.data?.detail || 'Failed to send test notification',
      })
      setTimeout(() => setTestResult(null), 5000)
    },
  })

  const jiraTestMutation = useMutation({
    mutationFn: testJiraConnection,
    onSuccess: (response: any) => {
      setJiraTestResult({ success: true, message: response.data?.message || 'Connection successful!' })
      setTimeout(() => setJiraTestResult(null), 5000)
    },
    onError: (error: any) => {
      setJiraTestResult({
        success: false,
        message: error.response?.data?.detail || 'Failed to connect to JIRA',
      })
      setTimeout(() => setJiraTestResult(null), 5000)
    },
  })

  // IaC mutations
  const iacSyncMutation = useMutation({
    mutationFn: triggerIaCSync,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iac-config'] })
      queryClient.invalidateQueries({ queryKey: ['iac-syncs'] })
      setIacSyncResult({ success: true, message: 'Sync started! Check the IaC page for progress.' })
      setTimeout(() => setIacSyncResult(null), 5000)
    },
    onError: (error: any) => {
      setIacSyncResult({
        success: false,
        message: error.response?.data?.detail || 'Failed to trigger sync',
      })
      setTimeout(() => setIacSyncResult(null), 5000)
    },
  })

  const handleChange = () => {
    setHasChanges(true)
  }

  const handleSave = () => {
    updateMutation.mutate({
      is_enabled: isEnabled,
      min_severity: minSeverity,
      notify_on_new_findings: notifyOnNew,
      notify_on_regression: notifyOnRegression,
      notify_on_scan_complete: notifyOnScanComplete,
    })
  }

  if (isLoading || isLoadingJira || isLoadingIac || isLoadingIntegrations) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
      </div>
    )
  }

  const webhookConfigured = config?.data?.webhook_configured

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <Plug className="w-8 h-8 text-gray-600" />
        <h1 className="text-2xl font-bold">Integrations</h1>
      </div>

      {/* Slack Integration Section */}
      <div className={clsx('bg-white rounded-lg shadow', !getIntegrationEnabled('slack') && 'opacity-60')}>
        <div className="px-6 py-4 border-b flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Bell className="w-5 h-5 text-gray-500" />
            <h2 className="text-lg font-semibold">Slack Notifications</h2>
          </div>
          <button
            onClick={() => integrationMutation.mutate({ type: 'slack', isEnabled: !getIntegrationEnabled('slack') })}
            disabled={integrationMutation.isPending}
            className={clsx(
              'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
              getIntegrationEnabled('slack')
                ? 'bg-green-100 text-green-800 hover:bg-green-200'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            )}
          >
            <Power className="w-4 h-4" />
            {getIntegrationEnabled('slack') ? 'Enabled' : 'Disabled'}
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Webhook URL Status (from environment variable) */}
          <div>
            <label className="block font-medium text-gray-900 mb-1">Webhook URL</label>
            {webhookConfigured ? (
              <div className="bg-green-50 rounded-lg p-3">
                <p className="text-sm text-green-700 flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-600" />
                  Webhook URL is configured via <code className="bg-green-100 px-1 rounded">SLACK_WEBHOOK_URL</code> environment variable
                </p>
                {config?.data?.channel_name && (
                  <p className="text-sm text-green-700 mt-2">
                    Sending to channel: <span className="font-mono font-medium">#{config.data.channel_name}</span>
                  </p>
                )}
              </div>
            ) : (
              <div className="bg-yellow-50 rounded-lg p-3">
                <p className="text-sm text-yellow-700 flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-yellow-600" />
                  Not configured. Set <code className="bg-yellow-100 px-1 rounded">SLACK_WEBHOOK_URL</code> in your .env file
                </p>
              </div>
            )}
          </div>

          {/* Minimum Severity */}
          <div>
            <label className="block font-medium text-gray-900 mb-1">Minimum Severity</label>
            <p className="text-sm text-gray-500 mb-2">
              Only send notifications for findings at or above this severity level
            </p>
            <select
              value={minSeverity}
              onChange={(e) => {
                setMinSeverity(e.target.value)
                handleChange()
              }}
              className="w-full max-w-xs px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              {severityOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>

          {/* Notification Triggers */}
          <div>
            <label className="block font-medium text-gray-900 mb-2">Notification Triggers</label>
            <div className="space-y-3">
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={notifyOnNew}
                  onChange={(e) => {
                    setNotifyOnNew(e.target.checked)
                    handleChange()
                  }}
                  className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700">
                  New findings — Alert when new non-compliant resources are discovered
                </span>
              </label>
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={notifyOnRegression}
                  onChange={(e) => {
                    setNotifyOnRegression(e.target.checked)
                    handleChange()
                  }}
                  className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700">
                  Regressions — Alert when previously compliant resources become non-compliant
                </span>
              </label>
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={notifyOnScanComplete}
                  onChange={(e) => {
                    setNotifyOnScanComplete(e.target.checked)
                    handleChange()
                  }}
                  className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700">
                  Scan complete — Send a summary notification when scans finish
                </span>
              </label>
            </div>
          </div>

          {/* Test Result Message */}
          {testResult && (
            <div
              className={clsx(
                'p-4 rounded-lg flex items-center gap-3',
                testResult.success ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'
              )}
            >
              {testResult.success ? (
                <CheckCircle className="w-5 h-5 text-green-500" />
              ) : (
                <XCircle className="w-5 h-5 text-red-500" />
              )}
              {testResult.message}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-3 pt-4 border-t">
            <button
              onClick={handleSave}
              disabled={!hasChanges || updateMutation.isPending}
              className={clsx(
                'px-4 py-2 rounded-lg font-medium flex items-center gap-2',
                hasChanges
                  ? 'bg-blue-600 text-white hover:bg-blue-700'
                  : 'bg-gray-100 text-gray-400 cursor-not-allowed'
              )}
            >
              {updateMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Save Changes
            </button>
            <button
              onClick={() => testMutation.mutate()}
              disabled={!webhookConfigured || testMutation.isPending}
              className={clsx(
                'px-4 py-2 rounded-lg font-medium flex items-center gap-2',
                webhookConfigured
                  ? 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  : 'bg-gray-50 text-gray-400 cursor-not-allowed'
              )}
            >
              {testMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              Send Test Notification
            </button>
          </div>
        </div>
      </div>

      {/* Help Section */}
      <HelpSection title="How to set up Slack notifications">
        <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
          <li>Go to <a href="https://api.slack.com/apps" target="_blank" rel="noopener noreferrer" className="underline">api.slack.com/apps</a> and create a new app</li>
          <li>Enable "Incoming Webhooks" in your app settings</li>
          <li>Click "Add New Webhook to Workspace" and select a channel</li>
          <li>Add <code className="bg-blue-100 px-1 rounded">SLACK_WEBHOOK_URL=https://hooks.slack.com/...</code> to your .env file</li>
          <li>Restart the application and send a test notification</li>
        </ol>
      </HelpSection>

      {/* JIRA Integration Section */}
      <div className={clsx('bg-white rounded-lg shadow mt-8', !getIntegrationEnabled('jira') && 'opacity-60')}>
        <div className="px-6 py-4 border-b flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Ticket className="w-5 h-5 text-gray-500" />
            <h2 className="text-lg font-semibold">JIRA Ticket Creation</h2>
          </div>
          <button
            onClick={() => integrationMutation.mutate({ type: 'jira', isEnabled: !getIntegrationEnabled('jira') })}
            disabled={integrationMutation.isPending}
            className={clsx(
              'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
              getIntegrationEnabled('jira')
                ? 'bg-green-100 text-green-800 hover:bg-green-200'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            )}
          >
            <Power className="w-4 h-4" />
            {getIntegrationEnabled('jira') ? 'Enabled' : 'Disabled'}
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Configuration Status */}
          {jiraConfig?.data?.configured ? (
            <div className="bg-green-50 rounded-lg p-4">
              <div className="flex items-center gap-2 text-green-800">
                <CheckCircle className="w-5 h-5 text-green-600" />
                <span className="font-medium">JIRA integration configured</span>
              </div>
              <p className="text-sm text-green-700 mt-1">
                Tickets will be automatically created for compliance findings
              </p>
            </div>
          ) : (
            <div className="bg-yellow-50 rounded-lg p-4">
              <div className="flex items-center gap-2 text-yellow-800">
                <XCircle className="w-5 h-5 text-yellow-600" />
                <span className="font-medium">JIRA integration not configured</span>
              </div>
              <p className="text-sm text-yellow-700 mt-2">
                Set the following environment variables to enable JIRA integration:
              </p>
              <ul className="text-sm text-yellow-700 mt-2 font-mono space-y-1">
                <li>JIRA_BASE_URL</li>
                <li>JIRA_EMAIL</li>
                <li>JIRA_API_TOKEN</li>
                <li>JIRA_PROJECT_KEY</li>
                <li>JIRA_ISSUE_TYPE (optional)</li>
                <li>JIRA_ASSIGNEE_EMAIL (optional)</li>
              </ul>
            </div>
          )}

          {/* Current Configuration Display */}
          {jiraConfig?.data?.configured && (
            <div>
              <label className="block font-medium text-gray-900 mb-2">Current Configuration</label>
              <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                <div className="flex items-center gap-3">
                  <Ticket className="w-5 h-5 text-gray-500" />
                  <div>
                    <span className="text-sm text-gray-500">Base URL:</span>
                    <a
                      href={jiraConfig.data.base_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-2 font-mono text-blue-600 hover:underline"
                    >
                      {jiraConfig.data.base_url}
                    </a>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 flex items-center justify-center">
                    <div className="w-2 h-2 bg-gray-400 rounded-full" />
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">Project Key:</span>
                    <span className="ml-2 font-mono text-gray-900">{jiraConfig.data.project_key}</span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 flex items-center justify-center">
                    <div className="w-2 h-2 bg-gray-400 rounded-full" />
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">Issue Type:</span>
                    <span className="ml-2 font-mono text-gray-900">{jiraConfig.data.issue_type}</span>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 flex items-center justify-center">
                    <div className="w-2 h-2 bg-gray-400 rounded-full" />
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">Email:</span>
                    <span className="ml-2 font-mono text-gray-900">{jiraConfig.data.email}</span>
                  </div>
                </div>
                {jiraConfig.data.assignee_email && (
                  <div className="flex items-center gap-3">
                    <div className="w-5 h-5 flex items-center justify-center">
                      <div className="w-2 h-2 bg-gray-400 rounded-full" />
                    </div>
                    <div>
                      <span className="text-sm text-gray-500">Default Assignee:</span>
                      <span className="ml-2 font-mono text-gray-900">{jiraConfig.data.assignee_email}</span>
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-3">
                  <div className="w-5 h-5 flex items-center justify-center">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  </div>
                  <div>
                    <span className="text-sm text-gray-500">API Token:</span>
                    <span className="ml-2 text-green-600">Configured</span>
                  </div>
                </div>
              </div>
              <p className="text-xs text-gray-500 mt-2">
                To change these settings, modify the JIRA environment variables in your .env file and restart.
              </p>
            </div>
          )}

          {/* Test Result Message */}
          {jiraTestResult && (
            <div
              className={clsx(
                'p-4 rounded-lg flex items-center gap-3',
                jiraTestResult.success ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'
              )}
            >
              {jiraTestResult.success ? (
                <CheckCircle className="w-5 h-5 text-green-500" />
              ) : (
                <XCircle className="w-5 h-5 text-red-500" />
              )}
              {jiraTestResult.message}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-3 pt-4 border-t">
            <button
              onClick={() => jiraTestMutation.mutate()}
              disabled={!jiraConfig?.data?.configured || jiraTestMutation.isPending}
              className={clsx(
                'px-4 py-2 rounded-lg font-medium flex items-center gap-2',
                jiraConfig?.data?.configured
                  ? 'bg-blue-600 text-white hover:bg-blue-700'
                  : 'bg-gray-100 text-gray-400 cursor-not-allowed'
              )}
            >
              {jiraTestMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              Test Connection
            </button>
          </div>
        </div>
      </div>

      {/* JIRA Help Section */}
      <HelpSection title="How to set up JIRA integration">
        <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
          <li>Go to <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="underline">Atlassian API Tokens</a> page</li>
          <li>Click "Create API token" and give it a name (e.g., "Compliance Dashboard")</li>
          <li>Add the following to your <code className="bg-blue-100 px-1 rounded">.env</code> file:</li>
        </ol>
        <pre className="mt-2 bg-blue-100 p-3 rounded text-xs overflow-x-auto">
{`JIRA_BASE_URL=https://yourcompany.atlassian.net
JIRA_EMAIL=your-email@company.com
JIRA_API_TOKEN=your-api-token
JIRA_PROJECT_KEY=SEC
JIRA_ISSUE_TYPE=Bug`}
        </pre>
        <p className="text-sm text-blue-800 mt-2">
          Then restart the application with <code className="bg-blue-100 px-1 rounded">docker-compose up -d --build</code>
        </p>
      </HelpSection>

      {/* IaC (GitHub) Integration Section */}
      <div className={clsx('bg-white rounded-lg shadow mt-8', !getIntegrationEnabled('iac') && 'opacity-60')}>
        <div className="px-6 py-4 border-b flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FileCode2 className="w-5 h-5 text-gray-500" />
            <h2 className="text-lg font-semibold">IaC Scanning (GitHub Integration)</h2>
          </div>
          <button
            onClick={() => integrationMutation.mutate({ type: 'iac', isEnabled: !getIntegrationEnabled('iac') })}
            disabled={integrationMutation.isPending}
            className={clsx(
              'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
              getIntegrationEnabled('iac')
                ? 'bg-green-100 text-green-800 hover:bg-green-200'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            )}
          >
            <Power className="w-4 h-4" />
            {getIntegrationEnabled('iac') ? 'Enabled' : 'Disabled'}
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Configuration Status */}
          {iacConfig?.data?.configured ? (
            <div className="bg-green-50 rounded-lg p-4">
              <div className="flex items-center gap-2 text-green-800">
                <CheckCircle className="w-5 h-5 text-green-600" />
                <span className="font-medium">GitHub integration configured</span>
              </div>
              <p className="text-sm text-green-700 mt-1">
                Trivy scan results will be synced from GitHub Code Scanning API
              </p>
            </div>
          ) : (
            <div className="bg-yellow-50 rounded-lg p-4">
              <div className="flex items-center gap-2 text-yellow-800">
                <XCircle className="w-5 h-5 text-yellow-600" />
                <span className="font-medium">GitHub integration not configured</span>
              </div>
              <p className="text-sm text-yellow-700 mt-2">
                Set the following environment variables to enable IaC scanning:
              </p>
              <ul className="text-sm text-yellow-700 mt-2 font-mono space-y-1">
                <li>GITHUB_TOKEN</li>
                <li>IAC_GITHUB_OWNER</li>
                <li>IAC_GITHUB_REPO</li>
              </ul>
            </div>
          )}

          {/* Current Configuration Display */}
          {iacConfig?.data?.configured && (
            <div className="space-y-4">
              <div>
                <label className="block font-medium text-gray-900 mb-2">Repository Configuration</label>
                <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                  <div className="flex items-center gap-3">
                    <Github className="w-5 h-5 text-gray-500" />
                    <div>
                      <span className="text-sm text-gray-500">Repository:</span>
                      <a
                        href={`https://github.com/${iacConfig.data.owner}/${iacConfig.data.repo}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-2 font-mono text-blue-600 hover:underline"
                      >
                        {iacConfig.data.owner}/{iacConfig.data.repo}
                      </a>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="w-5 h-5 flex items-center justify-center">
                      <div className="w-2 h-2 bg-gray-400 rounded-full" />
                    </div>
                    <div>
                      <span className="text-sm text-gray-500">Branch:</span>
                      <span className="ml-2 font-mono text-gray-900">{iacConfig.data.branch}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="w-5 h-5 flex items-center justify-center">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                    </div>
                    <div>
                      <span className="text-sm text-gray-500">GitHub Token:</span>
                      <span className="ml-2 text-green-600">Configured</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Last Sync Info */}
              {iacConfig.data.last_sync && (
                <div>
                  <label className="block font-medium text-gray-900 mb-2">Last Sync</label>
                  <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">
                        {new Date(iacConfig.data.last_sync.completed_at || iacConfig.data.last_sync.started_at).toLocaleString()}
                      </span>
                      <span className={clsx(
                        'px-2 py-0.5 rounded text-xs font-medium',
                        iacConfig.data.last_sync.status === 'COMPLETED' ? 'bg-green-100 text-green-800' :
                        iacConfig.data.last_sync.status === 'FAILED' ? 'bg-red-100 text-red-800' :
                        'bg-blue-100 text-blue-800'
                      )}>
                        {iacConfig.data.last_sync.status}
                      </span>
                    </div>
                    {iacConfig.data.last_sync.status === 'COMPLETED' && (
                      <div className="flex items-center gap-4 pt-2 border-t border-gray-200">
                        <div className="text-sm">
                          <span className="text-gray-500">Total Alerts:</span>
                          <span className="ml-2 font-medium text-gray-900">{iacConfig.data.last_sync.total_alerts ?? 0}</span>
                        </div>
                        <div className="text-sm">
                          <span className="text-gray-500">Open:</span>
                          <span className={clsx(
                            'ml-2 font-medium',
                            (iacConfig.data.last_sync.open_alerts ?? 0) > 0 ? 'text-red-600' : 'text-green-600'
                          )}>
                            {iacConfig.data.last_sync.open_alerts ?? 0}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Sync Result Message */}
          {iacSyncResult && (
            <div
              className={clsx(
                'p-4 rounded-lg flex items-center gap-3',
                iacSyncResult.success ? 'bg-green-50 text-green-800' : 'bg-red-50 text-red-800'
              )}
            >
              {iacSyncResult.success ? (
                <CheckCircle className="w-5 h-5 text-green-500" />
              ) : (
                <XCircle className="w-5 h-5 text-red-500" />
              )}
              {iacSyncResult.message}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-3 pt-4 border-t">
            <button
              onClick={() => iacSyncMutation.mutate()}
              disabled={!iacConfig?.data?.configured || iacSyncMutation.isPending}
              className={clsx(
                'px-4 py-2 rounded-lg font-medium flex items-center gap-2',
                iacConfig?.data?.configured
                  ? 'bg-blue-600 text-white hover:bg-blue-700'
                  : 'bg-gray-100 text-gray-400 cursor-not-allowed'
              )}
            >
              {iacSyncMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <RefreshCw className="w-4 h-4" />
              )}
              Trigger Manual Sync
            </button>
          </div>
        </div>
      </div>

      {/* IaC Help Section */}
      <HelpSection title="How to set up IaC scanning">
        <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
          <li>Ensure Trivy is running in your GitHub Actions workflow with SARIF output</li>
          <li>Enable GitHub Code Scanning for your repository</li>
          <li>Create a GitHub Personal Access Token with <code className="bg-blue-100 px-1 rounded">security_events:read</code> permission</li>
          <li>Add the following to your <code className="bg-blue-100 px-1 rounded">.env</code> file:</li>
        </ol>
        <pre className="mt-2 bg-blue-100 p-3 rounded text-xs overflow-x-auto">
{`GITHUB_TOKEN=ghp_your_personal_access_token
IAC_GITHUB_OWNER=YourOrg
IAC_GITHUB_REPO=your-iac-repo
IAC_GITHUB_BRANCH=main`}
        </pre>
        <p className="text-sm text-blue-800 mt-2">
          Then restart the application with <code className="bg-blue-100 px-1 rounded">docker-compose up -d --build</code>
        </p>
      </HelpSection>
    </div>
  )
}
