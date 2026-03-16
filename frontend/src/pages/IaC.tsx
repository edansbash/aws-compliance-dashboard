import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  RefreshCw, CheckCircle, XCircle, Clock, Loader2, ExternalLink,
  AlertTriangle, FileCode, GitBranch, AlertCircle
} from 'lucide-react'
import {
  getIaCConfig, getIaCSummary, getIaCSyncs, getIaCFindings, triggerIaCSync
} from '../services/api'
import { clsx } from 'clsx'
import { formatDateTime, formatDate, formatTimeAgo } from '../utils/dateTime'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-200',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  LOW: 'bg-blue-100 text-blue-800 border-blue-200',
}

const STATE_COLORS: Record<string, string> = {
  open: 'bg-red-100 text-red-800',
  fixed: 'bg-green-100 text-green-800',
  dismissed: 'bg-gray-100 text-gray-800',
}

export default function IaC() {
  const [activeTab, setActiveTab] = useState<'overview' | 'syncs' | 'findings'>('overview')
  const [syncsPage, setSyncsPage] = useState(1)
  const [findingsPage, setFindingsPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [stateFilter, setStateFilter] = useState<string>('open')

  const queryClient = useQueryClient()

  // Fetch config
  const { data: configData } = useQuery({
    queryKey: ['iac-config'],
    queryFn: () => getIaCConfig(),
  })

  // Fetch summary
  const { data: summaryData, isLoading: summaryLoading } = useQuery({
    queryKey: ['iac-summary'],
    queryFn: () => getIaCSummary(),
    refetchInterval: 30000,
  })

  // Fetch syncs
  const { data: syncsData, isLoading: syncsLoading } = useQuery({
    queryKey: ['iac-syncs', syncsPage],
    queryFn: () => getIaCSyncs(syncsPage, 10),
    refetchInterval: 10000,
  })

  // Fetch findings
  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['iac-findings', findingsPage, severityFilter, stateFilter],
    queryFn: () => getIaCFindings({
      page: findingsPage,
      per_page: 20,
      severity: severityFilter || undefined,
      state: stateFilter || undefined,
    }),
    refetchInterval: 30000,
  })

  // Sync mutation
  const syncMutation = useMutation({
    mutationFn: () => triggerIaCSync(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iac-syncs'] })
      queryClient.invalidateQueries({ queryKey: ['iac-summary'] })
      queryClient.invalidateQueries({ queryKey: ['iac-findings'] })
    },
  })

  const config = configData?.data
  const summary = summaryData?.data
  const syncs = syncsData?.data?.items || []
  const syncsTotal = syncsData?.data?.total || 0
  const syncsPages = syncsData?.data?.pages || 1
  const findings = findingsData?.data?.items || []
  const findingsTotal = findingsData?.data?.total || 0
  const findingsPages = findingsData?.data?.pages || 1

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <CheckCircle className="w-5 h-5 text-green-500" />
      case 'FAILED':
        return <XCircle className="w-5 h-5 text-red-500" />
      case 'RUNNING':
        return <Loader2 className="w-5 h-5 text-blue-500 animate-spin" />
      default:
        return <Clock className="w-5 h-5 text-gray-500" />
    }
  }

  
  if (!config?.configured) {
    return (
      <div className="flex flex-col items-center justify-center h-96">
        <AlertCircle className="w-16 h-16 text-gray-400 mb-4" />
        <h2 className="text-xl font-semibold text-gray-600 mb-2">IaC Scanning Not Configured</h2>
        <p className="text-gray-500 text-center max-w-md">
          Set the following environment variables to enable IaC scanning:
        </p>
        <pre className="mt-4 bg-gray-100 p-4 rounded-lg text-sm">
          GITHUB_TOKEN=ghp_xxxx{'\n'}
          IAC_GITHUB_OWNER=your-org{'\n'}
          IAC_GITHUB_REPO=your-repo{'\n'}
          IAC_GITHUB_BRANCH=main
        </pre>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">Infrastructure as Code</h1>
          <p className="text-gray-500 flex items-center gap-2 mt-1">
            <GitBranch className="w-4 h-4" />
            {config?.owner}/{config?.repo}
            <span className="text-gray-400">({config?.branch})</span>
          </p>
        </div>
        <button
          onClick={() => syncMutation.mutate()}
          disabled={syncMutation.isPending}
          className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          <RefreshCw className={clsx('w-4 h-4', syncMutation.isPending && 'animate-spin')} />
          {syncMutation.isPending ? 'Syncing...' : 'Sync Now'}
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b mb-6">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('overview')}
            className={clsx(
              'pb-3 px-1 border-b-2 font-medium text-sm transition-colors',
              activeTab === 'overview'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('syncs')}
            className={clsx(
              'pb-3 px-1 border-b-2 font-medium text-sm transition-colors',
              activeTab === 'syncs'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            Sync History
          </button>
          <button
            onClick={() => setActiveTab('findings')}
            className={clsx(
              'pb-3 px-1 border-b-2 font-medium text-sm transition-colors flex items-center gap-2',
              activeTab === 'findings'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            Findings
            {summary?.by_state?.open > 0 && (
              <span className="bg-red-100 text-red-700 text-xs px-2 py-0.5 rounded-full">
                {summary.by_state.open}
              </span>
            )}
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-5 gap-4">
            <div className="bg-white rounded-lg shadow p-4">
              <div className="text-sm text-gray-500 mb-1">Open Alerts</div>
              <div className="text-3xl font-bold">{summary?.by_state?.open || 0}</div>
            </div>
            <div className="bg-white rounded-lg shadow p-4 border-l-4 border-red-500">
              <div className="text-sm text-gray-500 mb-1">Critical</div>
              <div className="text-3xl font-bold text-red-600">{summary?.by_severity?.CRITICAL || 0}</div>
            </div>
            <div className="bg-white rounded-lg shadow p-4 border-l-4 border-orange-500">
              <div className="text-sm text-gray-500 mb-1">High</div>
              <div className="text-3xl font-bold text-orange-600">{summary?.by_severity?.HIGH || 0}</div>
            </div>
            <div className="bg-white rounded-lg shadow p-4 border-l-4 border-yellow-500">
              <div className="text-sm text-gray-500 mb-1">Medium</div>
              <div className="text-3xl font-bold text-yellow-600">{summary?.by_severity?.MEDIUM || 0}</div>
            </div>
            <div className="bg-white rounded-lg shadow p-4 border-l-4 border-blue-500">
              <div className="text-sm text-gray-500 mb-1">Low</div>
              <div className="text-3xl font-bold text-blue-600">{summary?.by_severity?.LOW || 0}</div>
            </div>
          </div>

          {/* Recent Syncs */}
          <div className="bg-white rounded-lg shadow">
            <div className="px-4 py-3 border-b flex justify-between items-center">
              <h3 className="font-semibold">Recent Syncs</h3>
              <button
                onClick={() => setActiveTab('syncs')}
                className="text-sm text-blue-600 hover:text-blue-800"
              >
                View all →
              </button>
            </div>
            <div className="divide-y">
              {syncsLoading ? (
                <div className="p-4 text-center text-gray-500">Loading...</div>
              ) : syncs.length === 0 ? (
                <div className="p-4 text-center text-gray-500">No syncs yet</div>
              ) : (
                syncs.slice(0, 5).map((sync: any) => (
                  <div key={sync.id} className="px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {getStatusIcon(sync.status)}
                      <div>
                        <div className="text-sm font-medium">
                          {sync.status === 'COMPLETED' ? (
                            <span>
                              <span className={sync.open_alerts > 0 ? 'text-red-600' : 'text-green-600'}>
                                {sync.open_alerts} open
                              </span>
                              <span className="text-gray-400"> / {sync.total_alerts} total</span>
                            </span>
                          ) : sync.status === 'FAILED' ? (
                            <span className="text-red-600">Sync failed</span>
                          ) : (
                            <span>Syncing...</span>
                          )}
                        </div>
                        <div className="text-xs text-gray-500">
                          {sync.commit_sha?.slice(0, 7)} • {sync.branch}
                        </div>
                      </div>
                    </div>
                    <div className="text-xs text-gray-500">
                      {formatDateTime(sync.completed_at || sync.started_at)}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Top Findings */}
          <div className="bg-white rounded-lg shadow">
            <div className="px-4 py-3 border-b flex justify-between items-center">
              <h3 className="font-semibold">Open Findings</h3>
              <button
                onClick={() => setActiveTab('findings')}
                className="text-sm text-blue-600 hover:text-blue-800"
              >
                View all →
              </button>
            </div>
            <div className="divide-y">
              {findingsLoading ? (
                <div className="p-4 text-center text-gray-500">Loading...</div>
              ) : findings.length === 0 ? (
                <div className="p-4 text-center text-gray-500">No open findings</div>
              ) : (
                findings.slice(0, 5).map((finding: any) => (
                  <div key={finding.id} className="px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={clsx(
                        'px-2 py-0.5 rounded text-xs font-medium',
                        SEVERITY_COLORS[finding.severity]
                      )}>
                        {finding.severity}
                      </span>
                      <div>
                        <div className="text-sm font-medium">{finding.trivy_rule_id}</div>
                        <div className="text-xs text-gray-500 flex items-center gap-1">
                          <FileCode className="w-3 h-3" />
                          {finding.file_path}:{finding.start_line}
                        </div>
                      </div>
                    </div>
                    <a
                      href={finding.github_alert_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </a>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'syncs' && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 border-b">
              <tr>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Status</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Branch</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Commit</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Started</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Completed</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Results</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {syncsLoading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                    Loading...
                  </td>
                </tr>
              ) : syncs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                    No syncs yet. Click "Sync Now" to fetch alerts from GitHub.
                  </td>
                </tr>
              ) : (
                syncs.map((sync: any) => (
                  <tr key={sync.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(sync.status)}
                        <span>{sync.status}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">{sync.branch || '-'}</td>
                    <td className="px-4 py-3 text-sm font-mono">
                      {sync.commit_sha?.slice(0, 7) || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {formatDateTime(sync.started_at)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {formatDateTime(sync.completed_at)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {sync.status === 'COMPLETED' ? (
                        <div className="flex items-center gap-3">
                          <span className="text-gray-600">{sync.open_alerts} open</span>
                          {sync.new_alerts > 0 && (
                            <span className="text-red-600">+{sync.new_alerts} new</span>
                          )}
                          {sync.fixed_alerts > 0 && (
                            <span className="text-green-600">{sync.fixed_alerts} fixed</span>
                          )}
                        </div>
                      ) : sync.status === 'FAILED' ? (
                        <span className="text-red-600 text-xs">{sync.error_message}</span>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          <div className="px-4 py-3 border-t flex items-center justify-between">
            <div className="text-sm text-gray-500">
              Showing {syncs.length} of {syncsTotal} syncs
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setSyncsPage(p => Math.max(1, p - 1))}
                disabled={syncsPage === 1}
                className="px-3 py-1 border rounded disabled:opacity-50"
              >
                Previous
              </button>
              <span className="px-3 py-1">Page {syncsPage} of {syncsPages}</span>
              <button
                onClick={() => setSyncsPage(p => Math.min(syncsPages, p + 1))}
                disabled={syncsPage === syncsPages}
                className="px-3 py-1 border rounded disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'findings' && (
        <div>
          {/* Filters */}
          <div className="flex gap-4 mb-4">
            <select
              value={stateFilter}
              onChange={e => { setStateFilter(e.target.value); setFindingsPage(1) }}
              className="border rounded-lg px-3 py-2"
            >
              <option value="">All States</option>
              <option value="open">Open</option>
              <option value="fixed">Fixed</option>
              <option value="dismissed">Dismissed</option>
            </select>
            <select
              value={severityFilter}
              onChange={e => { setSeverityFilter(e.target.value); setFindingsPage(1) }}
              className="border rounded-lg px-3 py-2"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="w-full">
              <thead className="bg-gray-50 border-b">
                <tr>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">State</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Severity</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Rule</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">File</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">First Detected</th>
                  <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {findingsLoading ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                      Loading...
                    </td>
                  </tr>
                ) : findings.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                      No findings match the current filters.
                    </td>
                  </tr>
                ) : (
                  findings.map((finding: any) => (
                    <tr key={finding.id} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <span className={clsx(
                          'px-2 py-0.5 rounded text-xs font-medium',
                          STATE_COLORS[finding.github_alert_state]
                        )}>
                          {finding.github_alert_state}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx(
                          'px-2 py-0.5 rounded text-xs font-medium border',
                          SEVERITY_COLORS[finding.severity]
                        )}>
                          {finding.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div>
                          <div className="text-sm font-medium">{finding.trivy_rule_id}</div>
                          <div className="text-xs text-gray-500 max-w-xs truncate" title={finding.trivy_rule_description}>
                            {finding.trivy_rule_description}
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm">
                        <div className="flex items-center gap-1">
                          <FileCode className="w-4 h-4 text-gray-400" />
                          <span className="max-w-xs truncate" title={finding.file_path}>
                            {finding.file_path}
                          </span>
                          <span className="text-gray-400">:{finding.start_line}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500">
                        {formatDate(finding.first_detected_at)}
                      </td>
                      <td className="px-4 py-3">
                        <a
                          href={finding.github_alert_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-800 flex items-center gap-1 text-sm"
                        >
                          <ExternalLink className="w-4 h-4" />
                          View
                        </a>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>

            <div className="px-4 py-3 border-t flex items-center justify-between">
              <div className="text-sm text-gray-500">
                Showing {findings.length} of {findingsTotal} findings
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => setFindingsPage(p => Math.max(1, p - 1))}
                  disabled={findingsPage === 1}
                  className="px-3 py-1 border rounded disabled:opacity-50"
                >
                  Previous
                </button>
                <span className="px-3 py-1">Page {findingsPage} of {findingsPages}</span>
                <button
                  onClick={() => setFindingsPage(p => Math.min(findingsPages, p + 1))}
                  disabled={findingsPage === findingsPages}
                  className="px-3 py-1 border rounded disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
