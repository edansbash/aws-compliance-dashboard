import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { Search, Filter, ExternalLink, X } from 'lucide-react'
import { getFindings, getAccounts, getRegions, getJiraConfig } from '../services/api'
import { clsx } from 'clsx'

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH: 'bg-orange-100 text-orange-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  LOW: 'bg-blue-100 text-blue-800',
  INFO: 'bg-gray-100 text-gray-800',
}

const statusColors: Record<string, string> = {
  FAIL: 'bg-red-100 text-red-800',
  PASS: 'bg-green-100 text-green-800',
  ERROR: 'bg-gray-100 text-gray-800',
  EXCEPTION: 'bg-purple-100 text-purple-800',
}

const workflowColors: Record<string, string> = {
  OPEN: 'bg-gray-100 text-gray-800',
  ACKNOWLEDGED: 'bg-blue-100 text-blue-800',
  PLANNED: 'bg-purple-100 text-purple-800',
  IN_PROGRESS: 'bg-yellow-100 text-yellow-800',
  RESOLVED: 'bg-green-100 text-green-800',
}

export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams()

  // Read filters from URL params
  const page = parseInt(searchParams.get('page') || '1', 10)
  const filters = {
    status: searchParams.get('status') || '',
    workflow_status: searchParams.get('workflow_status') || '',
    severity: searchParams.get('severity') || '',
    account_id: searchParams.get('account_id') || '',
    region: searchParams.get('region') || '',
  }

  // Helper to update URL params
  const updateParams = (updates: Record<string, string>) => {
    const newParams = new URLSearchParams(searchParams)
    Object.entries(updates).forEach(([key, value]) => {
      if (value) {
        newParams.set(key, value)
      } else {
        newParams.delete(key)
      }
    })
    setSearchParams(newParams)
  }

  const setPage = (newPage: number | ((prev: number) => number)) => {
    const nextPage = typeof newPage === 'function' ? newPage(page) : newPage
    updateParams({ page: nextPage > 1 ? String(nextPage) : '' })
  }

  const setFilters = (newFilters: typeof filters) => {
    updateParams({
      status: newFilters.status,
      workflow_status: newFilters.workflow_status,
      severity: newFilters.severity,
      account_id: newFilters.account_id,
      region: newFilters.region,
      page: '', // Reset page when filters change
    })
  }

  const { data: accountsData } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => getAccounts(1, 100),
  })

  const { data: regionsData } = useQuery({
    queryKey: ['regions'],
    queryFn: () => getRegions(),
  })

  const { data: jiraConfig } = useQuery({
    queryKey: ['jira-config'],
    queryFn: getJiraConfig,
  })

  const accounts = accountsData?.data?.items || []
  const regions = regionsData?.data?.regions || ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']

  const activeFilterCount = Object.values(filters).filter(v => v !== '').length

  const clearFilters = () => {
    setSearchParams(new URLSearchParams())
  }

  const { data, isLoading } = useQuery({
    queryKey: ['findings', page, filters],
    queryFn: () => getFindings({
      page,
      per_page: 20,
      ...(filters.status && { status: filters.status }),
      ...(filters.workflow_status && { workflow_status: filters.workflow_status }),
      ...(filters.severity && { severity: filters.severity }),
      ...(filters.account_id && { account_id: filters.account_id }),
      ...(filters.region && { region: filters.region }),
    }),
  })

  const findings = data?.data?.items || []
  const total = data?.data?.total || 0
  const pages = data?.data?.pages || 1

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Findings</h1>
        <div className="flex items-center gap-4">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search..."
              className="pl-10 pr-4 py-2 border rounded-lg w-64"
            />
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4 mb-6">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-gray-500" />
            <span className="font-medium text-gray-700">Filters</span>
            {activeFilterCount > 0 && (
              <span className="bg-blue-100 text-blue-800 text-xs px-2 py-0.5 rounded-full">
                {activeFilterCount} active
              </span>
            )}
          </div>
          {activeFilterCount > 0 && (
            <button
              onClick={clearFilters}
              className="text-sm text-gray-500 hover:text-gray-700 flex items-center gap-1"
            >
              <X className="w-3 h-3" />
              Clear all
            </button>
          )}
        </div>
        <div className="grid grid-cols-5 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Account</label>
            <select
              value={filters.account_id}
              onChange={(e) => setFilters({ ...filters, account_id: e.target.value })}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Accounts</option>
              {accounts.map((acc: any) => (
                <option key={acc.id} value={acc.account_id}>
                  {acc.name} ({acc.account_id})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Region</label>
            <select
              value={filters.region}
              onChange={(e) => setFilters({ ...filters, region: e.target.value })}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Regions</option>
              {regions.map((region: string) => (
                <option key={region} value={region}>{region}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Status</label>
            <select
              value={filters.status}
              onChange={(e) => setFilters({ ...filters, status: e.target.value })}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Statuses</option>
              <option value="FAIL">Non-Compliant</option>
              <option value="PASS">Compliant</option>
              <option value="EXCEPTION">Exception</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Workflow</label>
            <select
              value={filters.workflow_status}
              onChange={(e) => setFilters({ ...filters, workflow_status: e.target.value })}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Workflow</option>
              <option value="OPEN">Open</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="PLANNED">Planned</option>
              <option value="IN_PROGRESS">In Progress</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Severity</label>
            <select
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Status</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Workflow</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Severity</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Resource</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Account</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Region</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Rule</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">JIRA</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500"></th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-gray-500">
                  Loading...
                </td>
              </tr>
            ) : findings.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-gray-500">
                  No findings found
                </td>
              </tr>
            ) : (
              findings.map((finding: any) => (
                <tr key={finding.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <span className={clsx('px-2 py-1 rounded text-xs font-medium', statusColors[finding.status])}>
                      {finding.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('px-2 py-1 rounded text-xs font-medium', workflowColors[finding.workflow_status])}>
                      {finding.workflow_status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('px-2 py-1 rounded text-xs font-medium', severityColors[finding.rule?.severity || 'INFO'])}>
                      {finding.rule?.severity || 'N/A'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium">{finding.resource_name}</div>
                    <div className="text-sm text-gray-500 truncate max-w-xs">{finding.resource_id}</div>
                  </td>
                  <td className="px-4 py-3 text-sm">{finding.account_id}</td>
                  <td className="px-4 py-3 text-sm">{finding.region}</td>
                  <td className="px-4 py-3 text-sm">{finding.rule?.name || 'N/A'}</td>
                  <td className="px-4 py-3 text-sm">
                    {finding.jira_ticket_key && jiraConfig?.data?.base_url ? (
                      <a
                        href={`${jiraConfig.data.base_url}/browse/${finding.jira_ticket_key}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800"
                      >
                        {finding.jira_ticket_key}
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    ) : (
                      <span className="text-gray-400">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/findings/${finding.id}`}
                      className="text-blue-600 hover:text-blue-800"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="px-4 py-3 border-t flex items-center justify-between">
          <div className="text-sm text-gray-500">
            Showing {findings.length} of {total} findings
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
