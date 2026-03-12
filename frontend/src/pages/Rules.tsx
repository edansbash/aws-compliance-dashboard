import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { getRules, updateRule, scanRule } from '../services/api'
import { clsx } from 'clsx'
import { ExternalLink, Play, Loader2, Filter, X, ChevronLeft, ChevronRight } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useScanStatus } from '../hooks/useScanStatus'

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH: 'bg-orange-100 text-orange-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  LOW: 'bg-blue-100 text-blue-800',
  INFO: 'bg-gray-100 text-gray-800',
}

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const STATUS_OPTIONS = ['Compliant', 'Non-Compliant']

const RULES_PER_PAGE = 50

export default function Rules() {
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  // Track which rule is currently being scanned via SSE
  // This is the rule ID (not scan ID) so we can show the loading state on the correct row
  const [activeScanRuleId, setActiveScanRuleId] = useState<string | null>(null)

  // SSE hook for real-time scan status updates
  // When scan completes, we invalidate queries to refresh the data and clear the active rule
  const { subscribe: subscribeToScan } = useScanStatus({
    onComplete: () => {
      // Scan finished successfully - refresh data and clear active state
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setActiveScanRuleId(null)
    },
    onError: () => {
      // Scan failed - still refresh and clear
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setActiveScanRuleId(null)
    },
  })

  // Read filters from URL params
  const page = parseInt(searchParams.get('page') || '1', 10)
  const severityFilter = searchParams.get('severity') || ''
  const resourceTypeFilter = searchParams.get('resourceType') || ''
  const statusFilter = searchParams.get('status') || ''

  const hasActiveFilters = severityFilter || resourceTypeFilter || statusFilter

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

  // Fetch all rules for the filter dropdowns (cached)
  const { data: allRulesData } = useQuery({
    queryKey: ['rules', 'all'],
    queryFn: () => getRules(1, 1000),
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  })

  // Fetch paginated rules for display (when no filters active)
  const { data, isLoading } = useQuery({
    queryKey: ['rules', hasActiveFilters ? 'all' : `page-${page}`],
    queryFn: () => getRules(hasActiveFilters ? 1 : page, hasActiveFilters ? 1000 : RULES_PER_PAGE),
  })

  const toggleRule = useMutation({
    mutationFn: ({ id, is_enabled }: { id: string; is_enabled: boolean }) =>
      updateRule(id, { is_enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
    },
  })

  const scanRuleMutation = useMutation({
    mutationFn: (ruleId: string) => scanRule(ruleId),
    onSuccess: (response: any, ruleId: string) => {
      // The API returns the scan object with its ID
      // Subscribe to SSE to get real-time status updates
      const scanId = response?.data?.id
      console.log('[Scan] Mutation success, response:', response, 'scanId:', scanId)
      if (scanId) {
        setActiveScanRuleId(ruleId)
        subscribeToScan(String(scanId))
      } else {
        console.error('[Scan] No scan ID in response')
      }
    },
  })

  const handleScanRule = (ruleId: string) => {
    if (scanRuleMutation.isPending) return // Prevent multiple scans
    scanRuleMutation.mutate(ruleId)
  }

  // Get rules from response
  const allRules = data?.data?.items || []
  const total = data?.data?.total || 0
  const serverPages = data?.data?.pages || 1

  // Get unique resource types for filter dropdown (from ALL rules, not just current page)
  const allRulesForFilters = allRulesData?.data?.items || []
  const resourceTypes = useMemo(() => {
    const types = new Set(allRulesForFilters.map((r: any) => r.resource_type))
    return Array.from(types).sort() as string[]
  }, [allRulesForFilters])

  // Filter and sort rules
  const filteredRules = useMemo(() => {
    return [...allRules]
      .filter((rule: any) => {
        if (severityFilter && rule.severity !== severityFilter) return false
        if (resourceTypeFilter && rule.resource_type !== resourceTypeFilter) return false
        if (statusFilter === 'Compliant' && rule.finding_count > 0) return false
        if (statusFilter === 'Non-Compliant' && rule.finding_count === 0) return false
        return true
      })
      .sort((a: any, b: any) => a.name.localeCompare(b.name))
  }, [allRules, severityFilter, resourceTypeFilter, statusFilter])

  // Client-side pagination when filters are active
  const pages = hasActiveFilters
    ? Math.ceil(filteredRules.length / RULES_PER_PAGE) || 1
    : serverPages

  const rules = hasActiveFilters
    ? filteredRules.slice((page - 1) * RULES_PER_PAGE, page * RULES_PER_PAGE)
    : filteredRules

  // Reset to page 1 when filters change
  const clearFilters = () => {
    setSearchParams(new URLSearchParams())
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Rules</h1>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow p-4 mb-4">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-gray-500" />
            <span className="text-sm font-medium text-gray-700">Filters:</span>
          </div>

          <select
            value={severityFilter}
            onChange={(e) => updateParams({ severity: e.target.value, page: '' })}
            className="px-3 py-1.5 border rounded-lg text-sm bg-white"
          >
            <option value="">All Severities</option>
            {SEVERITY_OPTIONS.map((sev) => (
              <option key={sev} value={sev}>{sev}</option>
            ))}
          </select>

          <select
            value={resourceTypeFilter}
            onChange={(e) => updateParams({ resourceType: e.target.value, page: '' })}
            className="px-3 py-1.5 border rounded-lg text-sm bg-white"
          >
            <option value="">All Resource Types</option>
            {resourceTypes.map((type) => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={(e) => updateParams({ status: e.target.value, page: '' })}
            className="px-3 py-1.5 border rounded-lg text-sm bg-white"
          >
            <option value="">All Statuses</option>
            {STATUS_OPTIONS.map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>

          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1 px-2 py-1 text-sm text-gray-600 hover:text-gray-800"
            >
              <X className="w-4 h-4" />
              Clear filters
            </button>
          )}

          <span className="text-sm text-gray-500 ml-auto">
            {hasActiveFilters
              ? `${filteredRules.length} rules match filters`
              : `${total} rules total`}
          </span>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        {/* Top Pagination */}
        <div className="px-4 py-3 border-b flex items-center justify-between">
          <div className="text-sm text-gray-500">
            Showing {rules.length} of {hasActiveFilters ? filteredRules.length : total} rules (Page {page} of {pages})
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 text-sm border rounded hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
            >
              <ChevronLeft className="w-4 h-4" />
              Previous
            </button>
            <button
              onClick={() => setPage(p => Math.min(pages, p + 1))}
              disabled={page === pages}
              className="px-3 py-1 text-sm border rounded hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1"
            >
              Next
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Enabled</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Rule</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Severity</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Resource Type</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Findings</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Status</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Remediation</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                  Loading...
                </td>
              </tr>
            ) : rules.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                  No rules found. Run a scan to sync rules.
                </td>
              </tr>
            ) : (
              rules.map((rule: any) => (
                <tr key={rule.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleRule.mutate({
                        id: rule.id,
                        is_enabled: !rule.is_enabled,
                      })}
                      className={clsx(
                        'w-10 h-6 rounded-full relative transition-colors',
                        rule.is_enabled ? 'bg-blue-600' : 'bg-gray-300'
                      )}
                    >
                      <span
                        className={clsx(
                          'absolute top-1 w-4 h-4 bg-white rounded-full transition-transform',
                          rule.is_enabled ? 'left-5' : 'left-1'
                        )}
                      />
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium">{rule.name}</div>
                    <div className="text-sm text-gray-500">{rule.rule_id}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('px-2 py-1 rounded text-xs font-medium', severityColors[rule.severity])}>
                      {rule.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{rule.resource_type}</td>
                  <td className="px-4 py-3 text-sm">
                    <Link
                      to={`/rules/${rule.id}/findings`}
                      className="text-blue-600 hover:text-blue-800 hover:underline flex items-center gap-1"
                    >
                      {rule.finding_count || 0}
                      <ExternalLink className="w-3 h-3" />
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {rule.finding_count > 0 ? (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-red-100 text-red-800">
                        Non-Compliant
                      </span>
                    ) : (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-green-100 text-green-800">
                        Compliant
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {rule.has_remediation ? (
                      rule.remediation_tested ? (
                        <span className="text-green-600">Available</span>
                      ) : (
                        <span className="text-yellow-600">Not Tested</span>
                      )
                    ) : (
                      <span className="text-gray-400">Not available</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {(() => {
                        // Determine if this rule is currently being scanned
                        // We track by activeScanRuleId (set when mutation succeeds, cleared when SSE completes)
                        // Don't require isScanConnected because there's a brief gap between mutation success and SSE connect
                        const isThisRuleScanning = activeScanRuleId === rule.id
                        const isMutationPending = scanRuleMutation.isPending && scanRuleMutation.variables === rule.id
                        const isScanning = isThisRuleScanning || isMutationPending

                        return (
                          <button
                            onClick={() => handleScanRule(rule.id)}
                            disabled={isScanning}
                            className="flex items-center gap-1 px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {isScanning ? (
                              <>
                                <Loader2 className="w-3 h-3 animate-spin" />
                                Scanning
                              </>
                            ) : (
                              <>
                                <Play className="w-3 h-3" />
                                Scan
                              </>
                            )}
                          </button>
                        )
                      })()}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
