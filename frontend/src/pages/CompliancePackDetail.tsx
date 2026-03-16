import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useParams, Link, useSearchParams, useNavigate } from 'react-router-dom'
import { useState, useMemo } from 'react'
import { ArrowLeft, Plus, X, Search, ExternalLink, Play, Loader2, Filter } from 'lucide-react'
import { getCompliancePack, getRules, addRuleToCompliancePack, removeRuleFromCompliancePack, updateCompliancePack, updateRule, scanRule } from '../services/api'
import { clsx } from 'clsx'
import { formatDate } from '../utils/dateTime'

const severityColors: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH: 'bg-orange-100 text-orange-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  LOW: 'bg-blue-100 text-blue-800',
  INFO: 'bg-gray-100 text-gray-800',
}

const SEVERITY_OPTIONS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const STATUS_OPTIONS = ['Compliant', 'Non-Compliant']

export default function CompliancePackDetail() {
  const { id } = useParams()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [showAddRulesModal, setShowAddRulesModal] = useState(false)
  const [ruleSearch, setRuleSearch] = useState('')
  const [scanningRuleId, setScanningRuleId] = useState<string | null>(null)

  // Read filters from URL params
  const severityFilter = searchParams.get('severity') || ''
  const resourceTypeFilter = searchParams.get('resourceType') || ''
  const statusFilter = searchParams.get('status') || ''

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

  const { data: packData, isLoading: packLoading } = useQuery({
    queryKey: ['compliance-pack', id],
    queryFn: () => getCompliancePack(id!),
    enabled: !!id,
  })

  const { data: allRulesData } = useQuery({
    queryKey: ['rules'],
    queryFn: () => getRules(1, 200),
  })

  const toggleMutation = useMutation({
    mutationFn: (is_enabled: boolean) => updateCompliancePack(id!, { is_enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-pack', id] })
      queryClient.invalidateQueries({ queryKey: ['rules'] })
    },
  })

  const addRuleMutation = useMutation({
    mutationFn: (ruleId: string) => addRuleToCompliancePack(id!, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-pack', id] })
    },
  })

  const removeRuleMutation = useMutation({
    mutationFn: (ruleId: string) => removeRuleFromCompliancePack(id!, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-pack', id] })
    },
  })

  const toggleRuleMutation = useMutation({
    mutationFn: ({ ruleId, is_enabled }: { ruleId: string; is_enabled: boolean }) =>
      updateRule(ruleId, { is_enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-pack', id] })
      queryClient.invalidateQueries({ queryKey: ['rules'] })
    },
  })

  const scanRuleMutation = useMutation({
    mutationFn: (ruleId: string) => scanRule(ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-pack', id] })
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setScanningRuleId(null)
    },
    onError: () => {
      setScanningRuleId(null)
    },
  })

  const handleScanRule = (ruleId: string) => {
    setScanningRuleId(ruleId)
    scanRuleMutation.mutate(ruleId)
  }

  const pack = packData?.data
  const allRules = allRulesData?.data?.items || []
  const packRuleIds = new Set(pack?.rules?.map((r: any) => r.id) || [])
  const packRulesRaw = pack?.rules || []

  // Get unique resource types for filter dropdown
  const resourceTypes = useMemo(() => {
    const types = new Set(packRulesRaw.map((r: any) => r.resource_type))
    return Array.from(types).sort() as string[]
  }, [packRulesRaw])

  // Filter and sort pack rules
  const sortedPackRules = useMemo(() => {
    return [...packRulesRaw]
      .filter((rule: any) => {
        if (severityFilter && rule.severity !== severityFilter) return false
        if (resourceTypeFilter && rule.resource_type !== resourceTypeFilter) return false
        if (statusFilter === 'Compliant' && rule.finding_count > 0) return false
        if (statusFilter === 'Non-Compliant' && rule.finding_count === 0) return false
        return true
      })
      .sort((a: any, b: any) => a.name.localeCompare(b.name))
  }, [packRulesRaw, severityFilter, resourceTypeFilter, statusFilter])

  const hasActiveFilters = severityFilter || resourceTypeFilter || statusFilter

  const clearFilters = () => {
    setSearchParams(new URLSearchParams())
  }

  const availableRules = allRules.filter((rule: any) => !packRuleIds.has(rule.id))
  const filteredAvailableRules = availableRules
    .filter((rule: any) =>
      rule.name.toLowerCase().includes(ruleSearch.toLowerCase()) ||
      rule.rule_id.toLowerCase().includes(ruleSearch.toLowerCase())
    )
    .sort((a: any, b: any) => a.name.localeCompare(b.name))

  if (packLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Loading...</div>
      </div>
    )
  }

  if (!pack) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-500">Compliance pack not found</div>
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
          Back to Compliance Packs
        </button>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold mb-2">{pack.name}</h1>
              {pack.description && (
                <p className="text-gray-600 mb-4">{pack.description}</p>
              )}
              <div className="flex items-center gap-4">
                <span className="text-sm text-gray-500">
                  {pack.rules?.length || 0} rules
                </span>
                <span className="text-sm text-gray-500">
                  Created {formatDate(pack.created_at)}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-6">
              {/* Rule Compliance Score */}
              <div className="text-center border-r pr-6">
                <div className={clsx(
                  'text-3xl font-bold',
                  pack.compliance_score === 100 ? 'text-green-600' :
                  pack.compliance_score >= 80 ? 'text-yellow-600' : 'text-red-600'
                )}>
                  {pack.compliance_score?.toFixed(1) ?? 100}%
                </div>
                <div className="text-xs text-gray-500">Rule Compliance</div>
                <div className="text-xs text-gray-400 mt-1">
                  {pack.passing_rules ?? 0} / {(pack.passing_rules ?? 0) + (pack.failing_rules ?? 0)} rules passing
                </div>
              </div>
              {/* Resource Compliance Score */}
              <div className="text-center">
                <div className={clsx(
                  'text-3xl font-bold',
                  pack.resource_compliance_score === 100 ? 'text-green-600' :
                  pack.resource_compliance_score >= 80 ? 'text-yellow-600' : 'text-red-600'
                )}>
                  {pack.resource_compliance_score?.toFixed(1) ?? 100}%
                </div>
                <div className="text-xs text-gray-500">Resource Compliance</div>
                <div className="text-xs text-gray-400 mt-1">
                  {(pack.total_resources ?? 0) - (pack.failing_resources ?? 0)} / {pack.total_resources ?? 0} resources passing
                </div>
              </div>
              <div className="flex items-center gap-4 border-l pl-6">
                <span className="text-sm text-gray-600">
                  {pack.is_enabled ? 'Enabled' : 'Disabled'}
                </span>
                <button
                  onClick={() => toggleMutation.mutate(!pack.is_enabled)}
                  className={clsx(
                    'w-12 h-7 rounded-full relative transition-colors',
                    pack.is_enabled ? 'bg-blue-600' : 'bg-gray-300'
                  )}
                >
                  <span
                    className={clsx(
                      'absolute top-1 w-5 h-5 bg-white rounded-full transition-transform',
                      pack.is_enabled ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Rules in Pack */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <div className="px-4 py-3 border-b flex justify-between items-center">
          <h2 className="font-semibold">Rules in this Pack</h2>
          <button
            onClick={() => setShowAddRulesModal(true)}
            className="flex items-center gap-1 text-blue-600 hover:text-blue-800 text-sm"
          >
            <Plus className="w-4 h-4" />
            Add Rules
          </button>
        </div>

        {/* Filters */}
        <div className="px-4 py-3 border-b bg-gray-50">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-gray-500" />
              <span className="text-sm font-medium text-gray-700">Filters:</span>
            </div>

            <select
              value={severityFilter}
              onChange={(e) => updateParams({ severity: e.target.value })}
              className="px-3 py-1.5 border rounded-lg text-sm bg-white"
            >
              <option value="">All Severities</option>
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>{sev}</option>
              ))}
            </select>

            <select
              value={resourceTypeFilter}
              onChange={(e) => updateParams({ resourceType: e.target.value })}
              className="px-3 py-1.5 border rounded-lg text-sm bg-white"
            >
              <option value="">All Resource Types</option>
              {resourceTypes.map((type) => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>

            <select
              value={statusFilter}
              onChange={(e) => updateParams({ status: e.target.value })}
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
              Showing {sortedPackRules.length} of {packRulesRaw.length} rules
            </span>
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
            {sortedPackRules.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                  No rules in this pack. Click "Add Rules" to add some.
                </td>
              </tr>
            ) : (
              sortedPackRules.map((rule: any) => (
                <tr key={rule.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleRuleMutation.mutate({
                        ruleId: rule.id,
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
                      <span className="text-green-600">Available</span>
                    ) : (
                      <span className="text-gray-400">Not available</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleScanRule(rule.id)}
                        disabled={scanningRuleId === rule.id}
                        className="flex items-center gap-1 px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {scanningRuleId === rule.id ? (
                          <>
                            <Loader2 className="w-3 h-3 animate-spin" />
                            Scanning...
                          </>
                        ) : (
                          <>
                            <Play className="w-3 h-3" />
                            Scan
                          </>
                        )}
                      </button>
                      <button
                        onClick={() => removeRuleMutation.mutate(rule.id)}
                        className="text-red-600 hover:text-red-800 p-1"
                        title="Remove from pack"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add Rules Modal */}
      {showAddRulesModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg w-full max-w-2xl max-h-[80vh] flex flex-col">
            <div className="p-4 border-b">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Add Rules to Pack</h2>
                <button
                  onClick={() => {
                    setShowAddRulesModal(false)
                    setRuleSearch('')
                  }}
                  className="text-gray-500 hover:text-gray-700"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
              <div className="relative">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                <input
                  type="text"
                  value={ruleSearch}
                  onChange={(e) => setRuleSearch(e.target.value)}
                  placeholder="Search rules..."
                  className="w-full pl-10 pr-4 py-2 border rounded-lg"
                />
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-4">
              {filteredAvailableRules.length === 0 ? (
                <div className="text-center text-gray-500 py-8">
                  {availableRules.length === 0
                    ? 'All rules are already in this pack'
                    : 'No rules match your search'}
                </div>
              ) : (
                <div className="space-y-2">
                  {filteredAvailableRules.map((rule: any) => (
                    <div
                      key={rule.id}
                      className="flex items-center justify-between p-3 border rounded-lg hover:bg-gray-50"
                    >
                      <div>
                        <div className="font-medium">{rule.name}</div>
                        <div className="text-sm text-gray-500 flex items-center gap-2">
                          <span>{rule.rule_id}</span>
                          <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', severityColors[rule.severity])}>
                            {rule.severity}
                          </span>
                        </div>
                      </div>
                      <button
                        onClick={() => addRuleMutation.mutate(rule.id)}
                        disabled={addRuleMutation.isPending}
                        className="px-3 py-1 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
                      >
                        Add
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="p-4 border-t">
              <button
                onClick={() => {
                  setShowAddRulesModal(false)
                  setRuleSearch('')
                }}
                className="w-full px-4 py-2 border rounded-lg hover:bg-gray-50"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
