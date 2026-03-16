import { useQuery } from '@tanstack/react-query'
import { useState, useEffect, useRef } from 'react'
import { Eye, CheckCircle, XCircle, Clock, Loader2, FlaskConical, AlertTriangle } from 'lucide-react'
import { formatDateTime } from '../utils/dateTime'
import {
  getRemediationJobs,
  getAvailableRemediations,
} from '../services/api'

const STATUS_COLORS: Record<string, string> = {
  PENDING: 'bg-yellow-100 text-yellow-800',
  RUNNING: 'bg-blue-100 text-blue-800',
  COMPLETED: 'bg-green-100 text-green-800',
  FAILED: 'bg-red-100 text-red-800',
}

const STATUS_ICONS: Record<string, React.ReactNode> = {
  PENDING: <Clock className="w-4 h-4" />,
  RUNNING: <Loader2 className="w-4 h-4 animate-spin" />,
  COMPLETED: <CheckCircle className="w-4 h-4" />,
  FAILED: <XCircle className="w-4 h-4" />,
}

const LOG_LEVEL_COLORS: Record<string, string> = {
  ERROR: 'text-red-400',
  WARN: 'text-yellow-400',
  SUCCESS: 'text-green-400',
  INFO: 'text-cyan-400',
  DEBUG: 'text-gray-400',
}

interface LogEntry {
  message: string
  level: string
  timestamp?: string
}

interface LogViewerProps {
  jobId: string
  onClose: () => void
}

function LogViewer({ jobId, onClose }: LogViewerProps) {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [status, setStatus] = useState<string>('RUNNING')
  const logContainerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const eventSource = new EventSource(
      `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api/v1/remediation-jobs/${jobId}/logs/stream`
    )

    eventSource.onmessage = event => {
      const data = JSON.parse(event.data)
      if (data.type === 'log') {
        setLogs(prev => [...prev, {
          message: data.message,
          level: data.level || 'INFO',
          timestamp: data.timestamp
        }])
      } else if (data.type === 'status') {
        setStatus(data.status)
        if (data.status === 'COMPLETED' || data.status === 'FAILED') {
          eventSource.close()
        }
      }
    }

    eventSource.onerror = () => {
      eventSource.close()
    }

    return () => {
      eventSource.close()
    }
  }, [jobId])

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs])

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-3xl w-full mx-4 max-h-[80vh] flex flex-col">
        <div className="px-6 py-4 border-b flex items-center justify-between">
          <h2 className="text-lg font-semibold">Remediation Logs</h2>
          <span
            className={`px-2 py-1 rounded text-xs font-medium flex items-center gap-1 ${
              STATUS_COLORS[status] || 'bg-gray-100'
            }`}
          >
            {STATUS_ICONS[status]}
            {status}
          </span>
        </div>
        <div
          ref={logContainerRef}
          className="px-6 py-4 overflow-y-auto flex-1 bg-gray-900 font-mono text-sm"
        >
          {logs.length === 0 ? (
            <p className="text-gray-500">Waiting for logs...</p>
          ) : (
            logs.map((log, i) => (
              <div
                key={i}
                className={`whitespace-pre-wrap ${LOG_LEVEL_COLORS[log.level] || 'text-gray-400'}`}
              >
                {log.message}
              </div>
            ))
          )}
        </div>
        <div className="px-6 py-4 border-t flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 border rounded hover:bg-gray-50"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH: 'bg-orange-100 text-orange-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  LOW: 'bg-blue-100 text-blue-800',
  INFO: 'bg-gray-100 text-gray-800',
}

export default function Remediation() {
  const [page, setPage] = useState(1)
  const [viewLogsJobId, setViewLogsJobId] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'jobs' | 'available'>('jobs')

  const { data, isLoading } = useQuery({
    queryKey: ['remediation-jobs', page],
    queryFn: () => getRemediationJobs({ page, per_page: 20 }),
    refetchInterval: 5000, // Poll for status updates
  })

  const { data: availableData, isLoading: availableLoading } = useQuery({
    queryKey: ['available-remediations'],
    queryFn: () => getAvailableRemediations(),
  })

  const jobs = data?.data?.items || []
  const total = data?.data?.total || 0
  const pages = data?.data?.pages || 1

  const availableRemediations = availableData?.data?.items || []

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Remediation</h1>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('jobs')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'jobs'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Jobs
          </button>
          <button
            onClick={() => setActiveTab('available')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'available'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Available Remediations
            <span className="ml-2 bg-gray-100 text-gray-600 py-0.5 px-2 rounded-full text-xs">
              {availableRemediations.length}
            </span>
          </button>
        </nav>
      </div>

      {activeTab === 'available' && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 border-b">
              <tr>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                  Rule
                </th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                  Resource Type
                </th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                  Severity
                </th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                  Remediation Action
                </th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {availableLoading ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    Loading...
                  </td>
                </tr>
              ) : availableRemediations.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    No remediations available.
                  </td>
                </tr>
              ) : (
                availableRemediations.map((remediation: any) => (
                  <tr key={remediation.rule_id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="text-sm font-medium text-gray-900">
                        {remediation.name}
                      </div>
                      <div className="text-sm text-gray-500">
                        {remediation.rule_id}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-500">
                      {remediation.resource_type}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${
                          SEVERITY_COLORS[remediation.severity] || 'bg-gray-100'
                        }`}
                      >
                        {remediation.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700 max-w-md">
                      {remediation.remediation_description}
                    </td>
                    <td className="px-4 py-3">
                      {remediation.remediation_tested ? (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800">
                          <FlaskConical className="w-3 h-3" />
                          Tested
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-yellow-100 text-yellow-800">
                          <AlertTriangle className="w-3 h-3" />
                          Untested
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'jobs' && (

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Resource
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Account ID
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Region
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Rule
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Status
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Started
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Completed
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                  Loading...
                </td>
              </tr>
            ) : jobs.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                  No remediation jobs found. Remediation can be triggered from
                  the Finding Detail page.
                </td>
              </tr>
            ) : (
              jobs.map((job: any) => (
                <tr key={job.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-sm font-mono truncate max-w-xs">
                    {job.finding?.resource_name || job.finding?.resource_id}
                  </td>
                  <td className="px-4 py-3 text-sm font-mono">
                    {job.finding?.account_id || '-'}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {job.finding?.region || '-'}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {job.finding?.rule?.name || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium flex items-center gap-1 w-fit ${
                        STATUS_COLORS[job.status] || 'bg-gray-100'
                      }`}
                    >
                      {STATUS_ICONS[job.status]}
                      {job.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {formatDateTime(job.started_at)}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {formatDateTime(job.completed_at)}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => setViewLogsJobId(job.id)}
                      className="text-blue-600 hover:text-blue-800 flex items-center gap-1 text-sm"
                    >
                      <Eye className="w-4 h-4" />
                      View Logs
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        <div className="px-4 py-3 border-t flex items-center justify-between">
          <div className="text-sm text-gray-500">
            Showing {jobs.length} of {total} jobs
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 border rounded disabled:opacity-50"
            >
              Previous
            </button>
            <span className="px-3 py-1">
              Page {page} of {pages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(pages, p + 1))}
              disabled={page === pages}
              className="px-3 py-1 border rounded disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      </div>
      )}

      {viewLogsJobId && (
        <LogViewer
          jobId={viewLogsJobId}
          onClose={() => setViewLogsJobId(null)}
        />
      )}
    </div>
  )
}
