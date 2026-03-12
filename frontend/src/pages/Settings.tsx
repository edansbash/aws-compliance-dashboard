import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Settings as SettingsIcon, Bell, Send, CheckCircle, XCircle, Loader2, Eye, EyeOff, Ticket } from 'lucide-react'
import { getSlackConfig, updateSlackConfig, testSlackNotification, getJiraConfig, updateJiraConfig, testJiraConnection } from '../services/api'
import { clsx } from 'clsx'

const severityOptions = [
  { value: 'CRITICAL', label: 'Critical only', color: 'text-red-600' },
  { value: 'HIGH', label: 'High and above', color: 'text-orange-600' },
  { value: 'MEDIUM', label: 'Medium and above', color: 'text-yellow-600' },
  { value: 'LOW', label: 'Low and above', color: 'text-blue-600' },
  { value: 'INFO', label: 'All severities', color: 'text-gray-600' },
]


export default function Settings() {
  const queryClient = useQueryClient()

  // Slack state
  const [webhookUrl, setWebhookUrl] = useState('')
  const [showWebhook, setShowWebhook] = useState(false)
  const [isEnabled, setIsEnabled] = useState(false)
  const [minSeverity, setMinSeverity] = useState('CRITICAL')
  const [notifyOnNew, setNotifyOnNew] = useState(true)
  const [notifyOnRegression, setNotifyOnRegression] = useState(true)
  const [notifyOnScanComplete, setNotifyOnScanComplete] = useState(true)
  const [hasChanges, setHasChanges] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)

  // JIRA state (credentials come from environment variables)
  const [jiraIsEnabled, setJiraIsEnabled] = useState(false)
  const [jiraMinSeverity, setJiraMinSeverity] = useState('CRITICAL')
  const [jiraNotifyOnNew, setJiraNotifyOnNew] = useState(true)
  const [jiraNotifyOnRegression, setJiraNotifyOnRegression] = useState(true)
  const [jiraHasChanges, setJiraHasChanges] = useState(false)
  const [jiraTestResult, setJiraTestResult] = useState<{ success: boolean; message: string } | null>(null)

  const { data: config, isLoading } = useQuery({
    queryKey: ['slack-config'],
    queryFn: () => getSlackConfig(),
  })

  const { data: jiraConfig, isLoading: isLoadingJira } = useQuery({
    queryKey: ['jira-config'],
    queryFn: () => getJiraConfig(),
  })

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

  // Sync JIRA form state when config data loads
  useEffect(() => {
    if (jiraConfig?.data) {
      setJiraIsEnabled(jiraConfig.data.is_enabled)
      setJiraMinSeverity(jiraConfig.data.min_severity)
      setJiraNotifyOnNew(jiraConfig.data.notify_on_new_findings)
      setJiraNotifyOnRegression(jiraConfig.data.notify_on_regression)
    }
  }, [jiraConfig])

  const updateMutation = useMutation({
    mutationFn: updateSlackConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['slack-config'] })
      setHasChanges(false)
      setWebhookUrl('') // Clear after save
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

  // JIRA mutations
  const jiraUpdateMutation = useMutation({
    mutationFn: updateJiraConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jira-config'] })
      setJiraHasChanges(false)
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

  const handleChange = () => {
    setHasChanges(true)
  }

  const handleSave = () => {
    const data: any = {
      is_enabled: isEnabled,
      min_severity: minSeverity,
      notify_on_new_findings: notifyOnNew,
      notify_on_regression: notifyOnRegression,
      notify_on_scan_complete: notifyOnScanComplete,
    }
    if (webhookUrl) {
      data.webhook_url = webhookUrl
    }
    updateMutation.mutate(data)
  }

  const handleJiraChange = () => {
    setJiraHasChanges(true)
  }

  const handleJiraSave = () => {
    const data: any = {
      is_enabled: jiraIsEnabled,
      min_severity: jiraMinSeverity,
      notify_on_new_findings: jiraNotifyOnNew,
      notify_on_regression: jiraNotifyOnRegression,
    }
    jiraUpdateMutation.mutate(data)
  }

  if (isLoading || isLoadingJira) {
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
        <SettingsIcon className="w-8 h-8 text-gray-600" />
        <h1 className="text-2xl font-bold">Settings</h1>
      </div>

      {/* Slack Integration Section */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b flex items-center gap-3">
          <Bell className="w-5 h-5 text-gray-500" />
          <h2 className="text-lg font-semibold">Slack Notifications</h2>
        </div>

        <div className="p-6 space-y-6">
          {/* Enable/Disable Toggle */}
          <div className="flex items-center justify-between">
            <div>
              <label className="font-medium text-gray-900">Enable Slack Notifications</label>
              <p className="text-sm text-gray-500">
                Send alerts to Slack when new compliance findings are detected
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                setIsEnabled(!isEnabled)
                handleChange()
              }}
              className={clsx(
                'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
                isEnabled ? 'bg-blue-600' : 'bg-gray-200'
              )}
            >
              <span
                className={clsx(
                  'pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out',
                  isEnabled ? 'translate-x-5' : 'translate-x-0'
                )}
              />
            </button>
          </div>

          {/* Webhook URL */}
          <div>
            <label className="block font-medium text-gray-900 mb-1">Webhook URL</label>
            <p className="text-sm text-gray-500 mb-2">
              Create an incoming webhook in your Slack workspace and paste the URL here
            </p>
            <div className="relative">
              <input
                type={showWebhook ? 'text' : 'password'}
                value={webhookUrl}
                onChange={(e) => {
                  setWebhookUrl(e.target.value)
                  handleChange()
                }}
                placeholder={webhookConfigured ? '••••••••••••••••••••' : 'https://hooks.slack.com/services/...'}
                className="w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 pr-10"
              />
              <button
                type="button"
                onClick={() => setShowWebhook(!showWebhook)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                {showWebhook ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
            {webhookConfigured && (
              <p className="mt-1 text-sm text-green-600 flex items-center gap-1">
                <CheckCircle className="w-4 h-4" />
                Webhook URL is configured
              </p>
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
      <div className="mt-6 bg-blue-50 rounded-lg p-4">
        <h3 className="font-medium text-blue-900 mb-2">How to set up Slack notifications</h3>
        <ol className="text-sm text-blue-800 space-y-1 list-decimal list-inside">
          <li>Go to <a href="https://api.slack.com/apps" target="_blank" rel="noopener noreferrer" className="underline">api.slack.com/apps</a> and create a new app</li>
          <li>Enable "Incoming Webhooks" in your app settings</li>
          <li>Click "Add New Webhook to Workspace" and select a channel</li>
          <li>Copy the webhook URL and paste it above</li>
          <li>Save your changes and send a test notification</li>
        </ol>
      </div>

      {/* JIRA Integration Section */}
      <div className="bg-white rounded-lg shadow mt-8">
        <div className="px-6 py-4 border-b flex items-center gap-3">
          <Ticket className="w-5 h-5 text-gray-500" />
          <h2 className="text-lg font-semibold">JIRA Ticket Creation</h2>
        </div>

        <div className="p-6 space-y-6">
          {/* Enable/Disable Toggle */}
          <div className="flex items-center justify-between">
            <div>
              <label className="font-medium text-gray-900">Enable JIRA Integration</label>
              <p className="text-sm text-gray-500">
                Automatically create JIRA tickets when new compliance findings are detected
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                setJiraIsEnabled(!jiraIsEnabled)
                handleJiraChange()
              }}
              className={clsx(
                'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2',
                jiraIsEnabled ? 'bg-blue-600' : 'bg-gray-200'
              )}
            >
              <span
                className={clsx(
                  'pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out',
                  jiraIsEnabled ? 'translate-x-5' : 'translate-x-0'
                )}
              />
            </button>
          </div>

          {/* Connection Status */}
          {jiraConfig?.data?.api_token_configured && (
            <div className="bg-green-50 rounded-lg p-4">
              <div className="flex items-center gap-2 text-green-800">
                <CheckCircle className="w-5 h-5 text-green-600" />
                <span className="font-medium">JIRA connection configured via environment variables</span>
              </div>
              <p className="text-sm text-green-700 mt-1">
                Project: <span className="font-mono">{jiraConfig.data.project_key}</span>
              </p>
            </div>
          )}

          {!jiraConfig?.data?.api_token_configured && (
            <div className="bg-yellow-50 rounded-lg p-4">
              <p className="text-sm text-yellow-800">
                JIRA connection not configured. Set the following environment variables:
              </p>
              <ul className="text-sm text-yellow-700 mt-2 font-mono space-y-1">
                <li>JIRA_BASE_URL</li>
                <li>JIRA_EMAIL</li>
                <li>JIRA_API_TOKEN</li>
                <li>JIRA_PROJECT_KEY</li>
                <li>JIRA_ISSUE_TYPE</li>
              </ul>
            </div>
          )}

          {/* Minimum Severity */}
          <div>
            <label className="block font-medium text-gray-900 mb-1">Minimum Severity</label>
            <p className="text-sm text-gray-500 mb-2">
              Only create tickets for findings at or above this severity level
            </p>
            <select
              value={jiraMinSeverity}
              onChange={(e) => {
                setJiraMinSeverity(e.target.value)
                handleJiraChange()
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

          {/* Due Date Info */}
          <div className="bg-gray-50 rounded-lg p-4">
            <h4 className="font-medium text-gray-900 mb-2">Due Dates by Severity</h4>
            <p className="text-sm text-gray-600 mb-2">
              Tickets are automatically assigned due dates based on finding severity:
            </p>
            <ul className="text-sm text-gray-600 space-y-1">
              <li><span className="font-medium text-red-600">Critical:</span> 15 days</li>
              <li><span className="font-medium text-orange-600">High:</span> 30 days</li>
              <li><span className="font-medium text-yellow-600">Medium:</span> 60 days</li>
              <li><span className="font-medium text-blue-600">Low:</span> 90 days</li>
            </ul>
          </div>

          {/* Notification Triggers */}
          <div>
            <label className="block font-medium text-gray-900 mb-2">Ticket Creation Triggers</label>
            <div className="space-y-3">
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={jiraNotifyOnNew}
                  onChange={(e) => {
                    setJiraNotifyOnNew(e.target.checked)
                    handleJiraChange()
                  }}
                  className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700">
                  New findings — Create tickets when new non-compliant resources are discovered
                </span>
              </label>
              <label className="flex items-center gap-3">
                <input
                  type="checkbox"
                  checked={jiraNotifyOnRegression}
                  onChange={(e) => {
                    setJiraNotifyOnRegression(e.target.checked)
                    handleJiraChange()
                  }}
                  className="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="text-gray-700">
                  Regressions — Create tickets when previously compliant resources become non-compliant
                </span>
              </label>
            </div>
          </div>

          {/* Ticket Structure Info */}
          <div className="bg-blue-50 rounded-lg p-4">
            <h4 className="font-medium text-blue-900 mb-2">Ticket Structure</h4>
            <p className="text-sm text-blue-800">
              A standalone ticket is created for each compliance finding with AWS Security Hub custom fields populated.
              Duplicate tickets are automatically prevented by checking for existing tickets with the same finding ID.
            </p>
          </div>

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
              onClick={handleJiraSave}
              disabled={!jiraHasChanges || jiraUpdateMutation.isPending}
              className={clsx(
                'px-4 py-2 rounded-lg font-medium flex items-center gap-2',
                jiraHasChanges
                  ? 'bg-blue-600 text-white hover:bg-blue-700'
                  : 'bg-gray-100 text-gray-400 cursor-not-allowed'
              )}
            >
              {jiraUpdateMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Save Changes
            </button>
            <button
              onClick={() => jiraTestMutation.mutate()}
              disabled={!jiraConfig?.data?.api_token_configured || jiraTestMutation.isPending}
              className={clsx(
                'px-4 py-2 rounded-lg font-medium flex items-center gap-2',
                jiraConfig?.data?.api_token_configured
                  ? 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  : 'bg-gray-50 text-gray-400 cursor-not-allowed'
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
      <div className="mt-6 bg-blue-50 rounded-lg p-4">
        <h3 className="font-medium text-blue-900 mb-2">How to set up JIRA integration</h3>
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
JIRA_ISSUE_TYPE=Bug
JIRA_ENABLED=true`}
        </pre>
        <p className="text-sm text-blue-800 mt-2">
          Then restart the application with <code className="bg-blue-100 px-1 rounded">docker-compose up -d --build</code>
        </p>
      </div>
    </div>
  )
}
