import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Download } from 'lucide-react'
import { getAuditLogs, exportAuditLogsCsv } from '../services/api'
import { formatDateTime, getISODateForFilename } from '../utils/dateTime'

const ACTION_COLORS: Record<string, string> = {
  SCAN_STARTED: 'bg-blue-100 text-blue-800',
  SCAN_COMPLETED: 'bg-green-100 text-green-800',
  FINDING_ACKNOWLEDGED: 'bg-yellow-100 text-yellow-800',
  FINDING_RESOLVED: 'bg-green-100 text-green-800',
  EXCEPTION_CREATED: 'bg-purple-100 text-purple-800',
  EXCEPTION_DELETED: 'bg-red-100 text-red-800',
  REMEDIATION_STARTED: 'bg-orange-100 text-orange-800',
  REMEDIATION_COMPLETED: 'bg-green-100 text-green-800',
  REMEDIATION_FAILED: 'bg-red-100 text-red-800',
  ACCOUNT_ADDED: 'bg-blue-100 text-blue-800',
  ACCOUNT_REMOVED: 'bg-red-100 text-red-800',
}

export default function AuditLogs() {
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState({
    action: '',
    user: '',
  })

  const { data, isLoading } = useQuery({
    queryKey: ['audit-logs', page, filters],
    queryFn: () => getAuditLogs({ page, per_page: 50, ...filters }),
  })

  const handleExport = async () => {
    try {
      const response = await exportAuditLogsCsv(filters)
      const blob = new Blob([response.data], { type: 'text/csv' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit-logs-${getISODateForFilename()}.csv`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      console.error('Failed to export audit logs:', error)
    }
  }

  const logs = data?.data?.items || []
  const total = data?.data?.total || 0
  const pages = data?.data?.pages || 1

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Audit Logs</h1>
        <button
          onClick={handleExport}
          className="flex items-center gap-2 border px-4 py-2 rounded hover:bg-gray-50"
        >
          <Download className="w-4 h-4" />
          Export CSV
        </button>
      </div>

      <div className="bg-white rounded-lg shadow p-4 mb-6">
        <div className="flex gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Action
            </label>
            <select
              value={filters.action}
              onChange={e => setFilters(f => ({ ...f, action: e.target.value }))}
              className="border rounded px-3 py-2"
            >
              <option value="">All Actions</option>
              <option value="SCAN_STARTED">Scan Started</option>
              <option value="SCAN_COMPLETED">Scan Completed</option>
              <option value="FINDING_ACKNOWLEDGED">Finding Acknowledged</option>
              <option value="FINDING_RESOLVED">Finding Resolved</option>
              <option value="EXCEPTION_CREATED">Exception Created</option>
              <option value="EXCEPTION_DELETED">Exception Deleted</option>
              <option value="REMEDIATION_STARTED">Remediation Started</option>
              <option value="REMEDIATION_COMPLETED">Remediation Completed</option>
              <option value="REMEDIATION_FAILED">Remediation Failed</option>
              <option value="ACCOUNT_ADDED">Account Added</option>
              <option value="ACCOUNT_REMOVED">Account Removed</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              User
            </label>
            <input
              type="text"
              value={filters.user}
              onChange={e => setFilters(f => ({ ...f, user: e.target.value }))}
              className="border rounded px-3 py-2"
              placeholder="Filter by user"
            />
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Timestamp
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Action
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                User
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Resource
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">
                Details
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  Loading...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  No audit logs found
                </td>
              </tr>
            ) : (
              logs.map((log: any) => (
                <tr key={log.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-sm">
                    {formatDateTime(log.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        ACTION_COLORS[log.action] || 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {log.action.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{log.user || 'System'}</td>
                  <td className="px-4 py-3 text-sm font-mono truncate max-w-xs">
                    {log.resource_type && log.resource_id
                      ? `${log.resource_type}/${log.resource_id}`
                      : '-'}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 truncate max-w-md">
                    {log.details ? JSON.stringify(log.details) : '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        <div className="px-4 py-3 border-t flex items-center justify-between">
          <div className="text-sm text-gray-500">
            Showing {logs.length} of {total} logs
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
    </div>
  )
}
