import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useParams, Link, useSearchParams, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import { useScanStatus } from '../hooks/useScanStatus'
import { ArrowLeft, ExternalLink, Filter, X, Wrench, Loader2, FileText, Search, Play, AlertTriangle, CheckCircle } from 'lucide-react'
import { getFindings, getRule, getAccounts, getRegions, createRemediationJob, createBulkExceptions, scanRule, previewRemediation, getJiraConfig } from '../services/api'
import { clsx } from 'clsx'
import JsonDiff from '../components/JsonDiff'
import { formatDateTime } from '../utils/dateTime'

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

function BulkRemediationPreviewModal({
  findingIds,
  onClose,
  onSuccess
}: {
  findingIds: string[]
  onClose: () => void
  onSuccess: () => void
}) {
  // Store the initial count to prevent it from changing when parent clears selection
  const [jobCount] = useState(findingIds.length)
  const [preview, setPreview] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [executing, setExecuting] = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    const fetchPreview = async () => {
      try {
        const response = await previewRemediation({ finding_ids: findingIds })
        setPreview(response.data)
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to load preview')
      } finally {
        setLoading(false)
      }
    }
    fetchPreview()
  }, [findingIds])

  const handleExecute = async () => {
    setExecuting(true)
    setError('')
    try {
      await createRemediationJob({
        finding_ids: findingIds,
        confirmed_by: 'user'
      })
      setSuccess(true)
      onSuccess()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to execute remediation')
      setExecuting(false)
    }
  }

  const handleViewJobs = () => {
    navigate('/remediation')
    onClose()
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-auto">
        <div className="px-6 py-4 border-b">
          <h2 className="text-lg font-semibold">Bulk Remediation Preview</h2>
          <p className="text-sm text-gray-600 mt-1">
            Review the changes that will be applied to {findingIds.length} resource(s)
          </p>
        </div>

        <div className="px-6 py-4">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
              <span className="ml-2 text-gray-600">Loading preview...</span>
            </div>
          ) : success ? (
            <div className="bg-green-50 border border-green-200 rounded-lg p-6 flex flex-col items-center gap-4">
              <CheckCircle className="w-12 h-12 text-green-600" />
              <div className="text-center">
                <p className="font-semibold text-green-800 text-lg">Remediation Jobs Queued</p>
                <p className="text-sm text-green-700 mt-2">
                  {jobCount} remediation job{jobCount !== 1 ? 's' : ''} created successfully.
                </p>
                <p className="text-sm text-green-700">
                  View progress on the Remediation page.
                </p>
              </div>
            </div>
          ) : error ? (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-red-800">Error</p>
                <p className="text-sm text-red-700">{error}</p>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <p className="text-sm text-blue-800">
                  <strong>{preview.findings.length}</strong> resource(s) will be remediated
                </p>
              </div>

              <div className="space-y-3 max-h-96 overflow-y-auto">
                {preview.findings.map((finding: any, idx: number) => (
                  <div key={idx} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <p className="font-medium text-sm">{finding.resource_name}</p>
                        <p className="text-xs text-gray-500 font-mono">{finding.resource_id}</p>
                      </div>
                      <span className="px-2 py-1 bg-orange-100 text-orange-800 text-xs rounded font-medium">
                        {finding.rule_name}
                      </span>
                    </div>

                    {finding.planned_action && (
                      <div className="mb-3">
                        <p className="text-xs text-gray-500 font-medium mb-1">Planned Action</p>
                        {finding.planned_action.includes('WARNING:') ? (
                          <div className="space-y-2">
                            <p className="text-sm text-gray-700">{finding.planned_action.split('WARNING:')[0].trim()}</p>
                            <div className="bg-red-600 text-white rounded-lg p-3 shadow-md">
                              <div className="flex items-start gap-2">
                                <span className="text-lg">⚠️</span>
                                <div>
                                  <p className="font-bold text-sm">WARNING</p>
                                  <p className="text-sm mt-1">{finding.planned_action.split('WARNING:')[1].trim()}</p>
                                </div>
                              </div>
                            </div>
                          </div>
                        ) : (
                          <p className="text-sm text-gray-700">{finding.planned_action}</p>
                        )}
                      </div>
                    )}

                    {finding.preview && (
                      <div>
                        <p className="text-xs text-gray-500 font-medium mb-1">Changes</p>
                        <JsonDiff
                          before={finding.preview.before}
                          after={finding.preview.after}
                        />
                      </div>
                    )}

                    {finding.actions && finding.actions.length > 0 && (
                      <div className="mt-3">
                        <p className="text-xs text-gray-500 font-medium mb-1">Actions</p>
                        <ul className="list-disc list-inside text-xs text-gray-700">
                          {finding.actions.map((action: string, i: number) => (
                            <li key={i}>{action}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t flex items-center justify-between bg-gray-50">
          {success ? (
            <>
              <div className="text-sm text-green-600">
                Jobs are being processed by the worker
              </div>
              <div className="flex gap-2">
                <button
                  onClick={onClose}
                  className="px-4 py-2 border rounded-lg hover:bg-gray-100"
                >
                  Close
                </button>
                <button
                  onClick={handleViewJobs}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  View Remediation Page
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="text-sm text-gray-600">
                {error ? (
                  <span className="text-red-600">Cannot proceed with remediation due to errors</span>
                ) : (
                  <span>Review the changes carefully before proceeding</span>
                )}
              </div>
              <div className="flex gap-2">
                <button
                  onClick={onClose}
                  className="px-4 py-2 border rounded-lg hover:bg-gray-100"
                  disabled={executing}
                >
                  Cancel
                </button>
                <button
                  onClick={handleExecute}
                  disabled={executing || loading || !!error}
                  className="flex items-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {executing ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Executing...
                    </>
                  ) : (
                    <>
                      <Wrench className="w-4 h-4" />
                      Confirm & Execute
                    </>
                  )}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default function RuleFindings() {
  const { id } = useParams()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [isScanning, setIsScanning] = useState(false)
  const [showExceptionModal, setShowExceptionModal] = useState(false)

  // SSE hook for real-time scan status updates
  const { subscribe: subscribeToScan } = useScanStatus({
    onComplete: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setIsScanning(false)
    },
    onError: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setIsScanning(false)
    },
  })
  const [showRemediationPreview, setShowRemediationPreview] = useState(false)
  const [exceptionForm, setExceptionForm] = useState({
    justification: '',
    expires_at: '',
    created_by: '',
  })

  // Read filters from URL params (default status to FAIL)
  const page = parseInt(searchParams.get('page') || '1', 10)
  const searchQuery = searchParams.get('search') || ''
  const filters = {
    status: searchParams.get('status') ?? 'FAIL',
    workflow_status: searchParams.get('workflow_status') || '',
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

  const setFilters = (newFilters: typeof filters | ((prev: typeof filters) => typeof filters)) => {
    const nextFilters = typeof newFilters === 'function' ? newFilters(filters) : newFilters
    updateParams({
      status: nextFilters.status,
      workflow_status: nextFilters.workflow_status,
      account_id: nextFilters.account_id,
      region: nextFilters.region,
      page: '', // Reset page when filters change
    })
  }

  const { data: ruleData, isLoading: ruleLoading } = useQuery({
    queryKey: ['rule', id],
    queryFn: () => getRule(id!),
    enabled: !!id,
  })

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
    setFilters({
      status: '',
      workflow_status: '',
      account_id: '',
      region: '',
    })
  }

  const { data, isLoading } = useQuery({
    queryKey: ['findings', 'rule', id, page, filters, searchQuery],
    queryFn: () => getFindings({
      rule_id: id,
      page,
      per_page: 20,
      ...(filters.status && { status: filters.status }),
      ...(filters.workflow_status && { workflow_status: filters.workflow_status }),
      ...(filters.account_id && { account_id: filters.account_id }),
      ...(filters.region && { region: filters.region }),
      ...(searchQuery && { search: searchQuery }),
    }),
    enabled: !!id,
  })

  const rule = ruleData?.data
  const findings = data?.data?.items || []
  const total = data?.data?.total || 0
  const pages = data?.data?.pages || 1

  // FAIL findings for selection (for remediation or exception)
  const failingFindingIds = findings
    .filter((f: any) => f.status === 'FAIL')
    .map((f: any) => f.id)

  const createExceptionsMutation = useMutation({
    mutationFn: (data: { finding_ids: string[]; justification: string; created_by: string; expires_at?: string }) =>
      createBulkExceptions(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['exceptions'] })
      setSelectedIds(new Set())
      setShowExceptionModal(false)
      setExceptionForm({ justification: '', expires_at: '', created_by: '' })
    },
  })

  const scanRuleMutation = useMutation({
    mutationFn: () => scanRule(id!),
    onSuccess: (response: any) => {
      // Subscribe to SSE for real-time status updates
      const scanId = response?.data?.id
      console.log('[Scan] Mutation success, response:', response, 'scanId:', scanId)
      if (scanId) {
        subscribeToScan(String(scanId))
      } else {
        console.error('[Scan] No scan ID in response')
        setIsScanning(false)
      }
    },
    onError: () => {
      setIsScanning(false)
    },
  })

  const handleScanRule = () => {
    setIsScanning(true)
    scanRuleMutation.mutate()
  }

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedIds(new Set(failingFindingIds))
    } else {
      setSelectedIds(new Set())
    }
  }

  const handleSelectOne = (findingId: string, checked: boolean) => {
    const newSet = new Set(selectedIds)
    if (checked) {
      newSet.add(findingId)
    } else {
      newSet.delete(findingId)
    }
    setSelectedIds(newSet)
  }

  const handleRemediateAll = () => {
    // Set all failing finding IDs as selected and show preview
    setSelectedIds(new Set(failingFindingIds))
    setShowRemediationPreview(true)
  }

  const handleRemediateSelected = () => {
    setShowRemediationPreview(true)
  }

  const handleRemediationSuccess = () => {
    queryClient.invalidateQueries({ queryKey: ['findings'] })
    queryClient.invalidateQueries({ queryKey: ['rules'] })
    setSelectedIds(new Set())
  }

  const handleCreateExceptions = () => {
    const data: { finding_ids: string[]; justification: string; created_by: string; expires_at?: string } = {
      finding_ids: Array.from(selectedIds),
      justification: exceptionForm.justification,
      created_by: exceptionForm.created_by || 'user',
    }
    if (exceptionForm.expires_at) {
      data.expires_at = exceptionForm.expires_at
    }
    createExceptionsMutation.mutate(data)
  }

  const allSelected = failingFindingIds.length > 0 &&
    failingFindingIds.every((id: string) => selectedIds.has(id))
  const someSelected = selectedIds.size > 0

  if (ruleLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading rule...</div>
      </div>
    )
  }

  if (!rule) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Rule not found</div>
      </div>
    )
  }

  return (
    <div>
      {/* Header */}
      <div className="mb-6">
        <button
          onClick={() => navigate(-1)}
          className="text-blue-600 hover:text-blue-800 flex items-center gap-1 mb-4"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Rules
        </button>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold mb-2">{rule.name}</h1>
              <p className="text-gray-600 mb-4">{rule.description}</p>
              <div className="flex items-center gap-4 text-sm">
                <span className={clsx('px-2 py-1 rounded text-xs font-medium', severityColors[rule.severity])}>
                  {rule.severity}
                </span>
                <span className="text-gray-500">Resource Type: {rule.resource_type}</span>
                <span className="text-gray-500">Rule ID: {rule.rule_id}</span>
              </div>
            </div>
            <div className="flex flex-col items-end gap-3">
              <div className="flex items-center gap-3">
                <button
                  onClick={handleScanRule}
                  disabled={isScanning}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Scan Rule
                    </>
                  )}
                </button>
                {rule.has_remediation && (
                  <button
                    onClick={handleRemediateAll}
                    disabled={total === 0}
                    className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Wrench className="w-4 h-4" />
                    Remediate All
                  </button>
                )}
              </div>
              <div className={clsx(
                'flex items-center gap-2 px-3 py-1.5 rounded-lg',
                total > 0 ? 'bg-red-50 border border-red-200' : 'bg-green-50 border border-green-200'
              )}>
                <span className={clsx(
                  'text-xl font-bold',
                  total > 0 ? 'text-red-700' : 'text-green-700'
                )}>
                  {total}
                </span>
                <span className={clsx(
                  'text-sm',
                  total > 0 ? 'text-red-600' : 'text-green-600'
                )}>
                  {filters.status === 'FAIL' ? 'Non-Compliant' : 'Resources'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="bg-white rounded-lg shadow p-4 mb-6">
        {/* Search Bar */}
        <div className="mb-4">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => updateParams({ search: e.target.value, page: '' })}
              placeholder="Search by resource name or ID..."
              className="w-full pl-10 pr-4 py-2 border rounded-lg text-sm"
            />
            {searchQuery && (
              <button
                onClick={() => updateParams({ search: '', page: '' })}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

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
        <div className="grid grid-cols-4 gap-4">
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
        </div>
      </div>

      {/* Bulk Actions Bar */}
      {someSelected && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-blue-800 font-medium">{selectedIds.size} finding(s) selected</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSelectedIds(new Set())}
              className="px-3 py-1 text-sm text-gray-600 hover:text-gray-800"
            >
              Clear selection
            </button>
            <button
              onClick={() => setShowExceptionModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700"
            >
              <FileText className="w-4 h-4" />
              Write Justification
            </button>
            {rule.has_remediation && (
              <button
                onClick={handleRemediateSelected}
                disabled={selectedIds.size === 0}
                className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Wrench className="w-4 h-4" />
                Remediate Selected
              </button>
            )}
          </div>
        </div>
      )}

      {/* Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <th className="px-4 py-3 w-10">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={(e) => handleSelectAll(e.target.checked)}
                  className="rounded border-gray-300"
                  disabled={failingFindingIds.length === 0}
                />
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Status</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Workflow</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Resource</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Account</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Region</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Last Scanned</th>
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
                  No resources found for this rule
                </td>
              </tr>
            ) : (
              findings.map((finding: any) => (
                <tr key={finding.id} className={clsx('hover:bg-gray-50', selectedIds.has(finding.id) && 'bg-blue-50')}>
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(finding.id)}
                      onChange={(e) => handleSelectOne(finding.id, e.target.checked)}
                      className="rounded border-gray-300"
                      disabled={finding.status !== 'FAIL'}
                    />
                  </td>
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
                    <div className="font-medium">{finding.resource_name}</div>
                    <div className="text-sm text-gray-500 truncate max-w-xs">{finding.resource_id}</div>
                  </td>
                  <td className="px-4 py-3 text-sm">{finding.account_id}</td>
                  <td className="px-4 py-3 text-sm">{finding.region}</td>
                  <td className="px-4 py-3 text-sm text-gray-500">
                    {formatDateTime(finding.last_scanned_at)}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {finding.jira_ticket_key && jiraConfig?.data?.base_url ? (
                      <a
                        href={`${jiraConfig.data.base_url}/browse/${finding.jira_ticket_key}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800"
                      >
                        {finding.jira_ticket_key}
                      </a>
                    ) : (
                      <span className="text-gray-400">-</span>
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
            Showing {findings.length} of {total} resources
            {someSelected && (
              <span className="ml-2 text-blue-600">({selectedIds.size} selected)</span>
            )}
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

      {/* Exception Modal */}
      {showExceptionModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg w-full max-w-md p-6">
            <h2 className="text-lg font-semibold mb-4">
              Create Exception for {selectedIds.size} Finding{selectedIds.size > 1 ? 's' : ''}
            </h2>
            <p className="text-sm text-gray-500 mb-4">
              This will create resource-level exceptions for the selected findings.
            </p>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Justification <span className="text-red-500">*</span>
                </label>
                <textarea
                  value={exceptionForm.justification}
                  onChange={(e) => setExceptionForm({ ...exceptionForm, justification: e.target.value })}
                  rows={4}
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  placeholder="Enter justification for this exception..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Created By
                </label>
                <input
                  type="text"
                  value={exceptionForm.created_by}
                  onChange={(e) => setExceptionForm({ ...exceptionForm, created_by: e.target.value })}
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  placeholder="Your name or email"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Expires At
                </label>
                <input
                  type="date"
                  value={exceptionForm.expires_at}
                  onChange={(e) => setExceptionForm({ ...exceptionForm, expires_at: e.target.value })}
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                />
                <p className="text-xs text-gray-500 mt-1">Leave empty for no expiration</p>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => {
                  setShowExceptionModal(false)
                  setExceptionForm({ justification: '', expires_at: '', created_by: '' })
                }}
                className="px-4 py-2 border rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateExceptions}
                disabled={createExceptionsMutation.isPending || !exceptionForm.justification}
                className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50"
              >
                {createExceptionsMutation.isPending ? 'Creating...' : 'Create Exceptions'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Remediation Preview Modal */}
      {showRemediationPreview && (
        <BulkRemediationPreviewModal
          findingIds={Array.from(selectedIds)}
          onClose={() => setShowRemediationPreview(false)}
          onSuccess={handleRemediationSuccess}
        />
      )}
    </div>
  )
}
