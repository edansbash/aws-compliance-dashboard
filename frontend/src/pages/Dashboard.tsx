import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { AlertTriangle, CheckCircle, XCircle, Clock, Play, Server, Building2, Box, Shield } from 'lucide-react'
import { getFindingsSummary, getScans, createScan, getAccounts, getRules } from '../services/api'
import { useState } from 'react'
import { formatDate, formatTime } from '../utils/dateTime'

export default function Dashboard() {
  const [isScanning, setIsScanning] = useState(false)

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['findings-summary'],
    queryFn: () => getFindingsSummary(),
  })

  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => getScans(1, 5),
  })

  const { data: accountsData } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => getAccounts(1, 100),
  })

  const { data: rulesData, isLoading: rulesLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: () => getRules(1, 1),
  })

  const handleTriggerScan = async () => {
    setIsScanning(true)
    try {
      await createScan({})
      // Refetch data after scan starts
      window.location.reload()
    } catch (error) {
      console.error('Failed to start scan:', error)
    } finally {
      setIsScanning(false)
    }
  }

  const summaryData = summary?.data || {
    compliance_score: 0,
    total_resources: 0,
    by_severity: {},
    failing_by_severity: {},
    by_severity_status: {},
    by_status: {},
    by_workflow_status: {},
    by_account: {},
    by_resource_type: {},
  }

  // Helper to format resource type for display
  const formatResourceType = (type: string) => {
    // Convert AWS::EC2::SecurityGroup to EC2 Security Group
    const parts = type.split('::')
    if (parts.length >= 3) {
      const service = parts[1] // EC2, IAM, S3, etc.
      // Add spaces before capitals, but keep consecutive capitals together (e.g., DBInstance -> DB Instance)
      const resource = parts[2].replace(/([A-Z]+)([A-Z][a-z])|([a-z])([A-Z])/g, '$1$3 $2$4').trim()
      return `${service} ${resource}`
    }
    return type
  }

  // Sort resource types by resource count descending
  const sortedResourceTypes = Object.entries(summaryData.by_resource_type || {})
    .sort(([, a]: [string, any], [, b]: [string, any]) => b.resource_count - a.resource_count)

  // Map account IDs to names (by AWS account ID)
  const accountMap: Record<string, string> = {}
  // Map by internal UUID for scan display
  const accountMapById: Record<string, any> = {}
  accountsData?.data?.items?.forEach((acc: any) => {
    accountMap[acc.account_id] = acc.name || acc.account_id
    accountMapById[acc.id] = acc
  })

  const getScanAccountsDisplay = (scanAccountIds: string[] | null) => {
    if (!scanAccountIds || scanAccountIds.length === 0) {
      return 'All accounts'
    }
    const resolvedAccounts = scanAccountIds
      .map(id => accountMapById[id])
      .filter(Boolean)

    if (resolvedAccounts.length === 0) {
      return `${scanAccountIds.length} account(s)`
    }

    if (resolvedAccounts.length === 1) {
      return resolvedAccounts[0].name
    }

    return `${resolvedAccounts.length} accounts`
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <button
          onClick={handleTriggerScan}
          disabled={isScanning}
          className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          <Play className="w-4 h-4" />
          {isScanning ? 'Starting...' : 'Trigger Scan'}
        </button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <div className="bg-white rounded-lg shadow p-6">
          <div className="text-gray-500 text-sm mb-1">Compliance Score</div>
          <div className="text-3xl font-bold text-blue-600">
            {summaryLoading ? '...' : `${summaryData.compliance_score}%`}
          </div>
          <div className="mt-2 bg-gray-200 rounded-full h-2">
            <div
              className="bg-blue-600 rounded-full h-2"
              style={{ width: `${summaryData.compliance_score}%` }}
            />
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
            <Shield className="w-4 h-4" />
            Total Rules
          </div>
          <div className="text-3xl font-bold text-gray-700">
            {rulesLoading ? '...' : (rulesData?.data?.total || 0)}
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
            <Server className="w-4 h-4" />
            Total Resources
          </div>
          <div className="text-3xl font-bold text-gray-700">
            {summaryLoading ? '...' : (summaryData.total_resources || 0)}
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <div className="text-gray-500 text-sm mb-1">Total Findings</div>
          <div className="text-3xl font-bold text-gray-700">
            {summaryLoading ? '...' : (
              (summaryData.by_status?.PASS || 0) +
              (summaryData.by_status?.FAIL || 0) +
              (summaryData.by_status?.EXCEPTION || 0)
            )}
          </div>
          <div className="text-sm text-red-600 mt-1">
            {summaryData.by_status?.FAIL || 0} non-compliant
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Findings by Severity */}
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">Findings by Severity</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2 text-sm font-medium text-gray-500">Severity</th>
                  <th className="text-right py-2 text-sm font-medium text-red-500">Non-Compliant</th>
                  <th className="text-right py-2 text-sm font-medium text-green-500">Compliant</th>
                  <th className="text-right py-2 text-sm font-medium text-yellow-500">Exception</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b">
                  <td className="py-2 font-medium text-red-600">Critical</td>
                  <td className="py-2 text-right font-semibold text-red-600">
                    {summaryData.by_severity_status?.CRITICAL?.FAIL || 0}
                  </td>
                  <td className="py-2 text-right text-green-600">
                    {summaryData.by_severity_status?.CRITICAL?.PASS || 0}
                  </td>
                  <td className="py-2 text-right text-yellow-600">
                    {summaryData.by_severity_status?.CRITICAL?.EXCEPTION || 0}
                  </td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 font-medium text-orange-600">High</td>
                  <td className="py-2 text-right font-semibold text-red-600">
                    {summaryData.by_severity_status?.HIGH?.FAIL || 0}
                  </td>
                  <td className="py-2 text-right text-green-600">
                    {summaryData.by_severity_status?.HIGH?.PASS || 0}
                  </td>
                  <td className="py-2 text-right text-yellow-600">
                    {summaryData.by_severity_status?.HIGH?.EXCEPTION || 0}
                  </td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 font-medium text-yellow-600">Medium</td>
                  <td className="py-2 text-right font-semibold text-red-600">
                    {summaryData.by_severity_status?.MEDIUM?.FAIL || 0}
                  </td>
                  <td className="py-2 text-right text-green-600">
                    {summaryData.by_severity_status?.MEDIUM?.PASS || 0}
                  </td>
                  <td className="py-2 text-right text-yellow-600">
                    {summaryData.by_severity_status?.MEDIUM?.EXCEPTION || 0}
                  </td>
                </tr>
                <tr className="border-b">
                  <td className="py-2 font-medium text-blue-600">Low</td>
                  <td className="py-2 text-right font-semibold text-red-600">
                    {summaryData.by_severity_status?.LOW?.FAIL || 0}
                  </td>
                  <td className="py-2 text-right text-green-600">
                    {summaryData.by_severity_status?.LOW?.PASS || 0}
                  </td>
                  <td className="py-2 text-right text-yellow-600">
                    {summaryData.by_severity_status?.LOW?.EXCEPTION || 0}
                  </td>
                </tr>
                <tr className="bg-gray-50 font-semibold">
                  <td className="py-2">Total</td>
                  <td className="py-2 text-right text-red-600">
                    {(summaryData.by_severity_status?.CRITICAL?.FAIL || 0) +
                     (summaryData.by_severity_status?.HIGH?.FAIL || 0) +
                     (summaryData.by_severity_status?.MEDIUM?.FAIL || 0) +
                     (summaryData.by_severity_status?.LOW?.FAIL || 0)}
                  </td>
                  <td className="py-2 text-right text-green-600">
                    {(summaryData.by_severity_status?.CRITICAL?.PASS || 0) +
                     (summaryData.by_severity_status?.HIGH?.PASS || 0) +
                     (summaryData.by_severity_status?.MEDIUM?.PASS || 0) +
                     (summaryData.by_severity_status?.LOW?.PASS || 0)}
                  </td>
                  <td className="py-2 text-right text-yellow-600">
                    {(summaryData.by_severity_status?.CRITICAL?.EXCEPTION || 0) +
                     (summaryData.by_severity_status?.HIGH?.EXCEPTION || 0) +
                     (summaryData.by_severity_status?.MEDIUM?.EXCEPTION || 0) +
                     (summaryData.by_severity_status?.LOW?.EXCEPTION || 0)}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-lg font-semibold">Recent Scans</h2>
            <Link to="/scans" className="text-blue-600 text-sm hover:underline">
              View All
            </Link>
          </div>
          <div className="space-y-3">
            {scansLoading ? (
              <div className="text-gray-500">Loading...</div>
            ) : scans?.data?.items?.length === 0 ? (
              <div className="text-gray-500">No scans yet</div>
            ) : (
              scans?.data?.items?.slice(0, 5).map((scan: any) => (
                <div key={scan.id} className="flex items-center justify-between py-2 border-b last:border-b-0">
                  <div className="flex items-center gap-3">
                    {scan.status === 'COMPLETED' ? (
                      <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0" />
                    ) : scan.status === 'RUNNING' ? (
                      <Clock className="w-5 h-5 text-blue-500 animate-spin flex-shrink-0" />
                    ) : scan.status === 'FAILED' ? (
                      <XCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
                    ) : (
                      <Clock className="w-5 h-5 text-gray-500 flex-shrink-0" />
                    )}
                    <div className="flex flex-col min-w-0">
                      <span className="text-sm font-medium">
                        {formatDate(scan.created_at)}{' '}
                        <span className="text-gray-400 font-normal">
                          {formatTime(scan.created_at)}
                        </span>
                      </span>
                      <div className="flex items-center gap-2 text-xs text-gray-500">
                        <span className="flex items-center gap-1">
                          <Building2 className="w-3 h-3" />
                          {getScanAccountsDisplay(scan.account_ids)}
                        </span>
                        {scan.resource_types && scan.resource_types.length > 0 && (
                          <>
                            <span className="text-gray-300">•</span>
                            <span
                              className="flex items-center gap-1 truncate"
                              title={scan.resource_types.map((t: string) => t.replace('AWS::', '')).join(', ')}
                            >
                              <Box className="w-3 h-3 flex-shrink-0" />
                              {scan.resource_types.length <= 2
                                ? scan.resource_types.map((t: string) => t.replace('AWS::', '')).join(', ')
                                : `${scan.resource_types.length} resource types`
                              }
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="text-sm text-right flex-shrink-0 ml-2">
                    {scan.status === 'RUNNING' ? (
                      <span className="text-blue-500">Scanning...</span>
                    ) : scan.status === 'COMPLETED' ? (
                      <div className="flex flex-col items-end">
                        <span className="text-green-600">{scan.total_resources - scan.total_findings} compliant</span>
                        <span className={scan.total_findings > 0 ? 'text-red-600 font-medium' : 'text-gray-400'}>
                          {scan.total_findings} non-compliant
                        </span>
                      </div>
                    ) : (
                      <span className="text-gray-400">-</span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Breakdown by Account */}
      {Object.keys(summaryData.by_account || {}).length > 0 && (
        <div className="mt-6 bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-2 mb-4">
            <Building2 className="w-5 h-5 text-gray-500" />
            <h2 className="text-lg font-semibold">Findings by Account</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr className="border-b">
                  <th rowSpan={2} className="text-left px-4 py-2 text-sm font-medium text-gray-500 align-bottom">Account</th>
                  <th rowSpan={2} className="text-right px-4 py-2 text-sm font-medium text-gray-500 align-bottom">Resources</th>
                  <th rowSpan={2} className="text-right px-4 py-2 text-sm font-medium text-gray-500 align-bottom border-r">Findings</th>
                  <th colSpan={3} className="text-center px-4 py-2 text-sm font-semibold text-gray-700 border-r bg-gray-100">Status</th>
                  <th colSpan={4} className="text-center px-4 py-2 text-sm font-semibold text-gray-700 border-r bg-gray-100">Non-Compliant by Severity</th>
                  <th rowSpan={2} className="text-right px-4 py-2 text-sm font-medium text-gray-500 align-bottom">Score</th>
                </tr>
                <tr className="border-b">
                  <th className="text-right px-4 py-2 text-sm font-medium text-green-600 bg-green-50">Compliant</th>
                  <th className="text-right px-4 py-2 text-sm font-medium text-red-600 bg-red-50">Non-Compliant</th>
                  <th className="text-right px-4 py-2 text-sm font-medium text-purple-600 bg-purple-50 border-r">Exception</th>
                  <th className="text-right px-4 py-2 text-sm font-medium text-red-500">Critical</th>
                  <th className="text-right px-4 py-2 text-sm font-medium text-orange-500">High</th>
                  <th className="text-right px-4 py-2 text-sm font-medium text-yellow-600">Medium</th>
                  <th className="text-right px-4 py-2 text-sm font-medium text-blue-500 border-r">Low</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {Object.entries(summaryData.by_account || {}).map(([accountId, data]: [string, any]) => {
                  const complianceRate = data.total > 0
                    ? (((data.passing + (data.exceptions || 0)) / data.total) * 100).toFixed(1)
                    : '100.0'
                  return (
                    <tr key={accountId} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <div className="font-medium">{accountMap[accountId] || accountId}</div>
                        <div className="text-xs text-gray-400">{accountId}</div>
                      </td>
                      <td className="px-4 py-3 text-right text-gray-600">{data.resource_count || 0}</td>
                      <td className="px-4 py-3 text-right font-medium border-r">{data.total}</td>
                      <td className="px-4 py-3 text-right text-green-600 bg-green-50/50">{data.passing}</td>
                      <td className="px-4 py-3 text-right text-red-600 bg-red-50/50">{data.failing}</td>
                      <td className="px-4 py-3 text-right text-purple-600 bg-purple-50/50 border-r">{data.exceptions || 0}</td>
                      <td className="px-4 py-3 text-right">
                        <span className={data.failing_by_severity?.CRITICAL > 0 ? 'text-red-600 font-semibold' : 'text-gray-400'}>
                          {data.failing_by_severity?.CRITICAL || 0}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className={data.failing_by_severity?.HIGH > 0 ? 'text-orange-600 font-semibold' : 'text-gray-400'}>
                          {data.failing_by_severity?.HIGH || 0}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className={data.failing_by_severity?.MEDIUM > 0 ? 'text-yellow-600 font-semibold' : 'text-gray-400'}>
                          {data.failing_by_severity?.MEDIUM || 0}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right border-r">
                        <span className={data.failing_by_severity?.LOW > 0 ? 'text-blue-600 font-semibold' : 'text-gray-400'}>
                          {data.failing_by_severity?.LOW || 0}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className={
                          Number(complianceRate) === 100 ? 'text-green-600' :
                          Number(complianceRate) >= 80 ? 'text-yellow-600' : 'text-red-600'
                        }>
                          {complianceRate}%
                        </span>
                      </td>
                    </tr>
                  )
                })}
                {/* Total Row */}
                {(() => {
                  const accounts = Object.values(summaryData.by_account || {}) as any[]
                  const totalResources = accounts.reduce((sum, d) => sum + (d.resource_count || 0), 0)
                  const totalFindings = accounts.reduce((sum, d) => sum + d.total, 0)
                  const totalPassing = accounts.reduce((sum, d) => sum + d.passing, 0)
                  const totalFailing = accounts.reduce((sum, d) => sum + d.failing, 0)
                  const totalExceptions = accounts.reduce((sum, d) => sum + (d.exceptions || 0), 0)
                  const totalCritical = accounts.reduce((sum, d) => sum + (d.failing_by_severity?.CRITICAL || 0), 0)
                  const totalHigh = accounts.reduce((sum, d) => sum + (d.failing_by_severity?.HIGH || 0), 0)
                  const totalMedium = accounts.reduce((sum, d) => sum + (d.failing_by_severity?.MEDIUM || 0), 0)
                  const totalLow = accounts.reduce((sum, d) => sum + (d.failing_by_severity?.LOW || 0), 0)
                  const overallCompliance = totalFindings > 0 ? (((totalPassing + totalExceptions) / totalFindings) * 100).toFixed(1) : '100.0'
                  return (
                    <tr className="bg-gray-50 font-semibold border-t-2">
                      <td className="px-4 py-3">Total</td>
                      <td className="px-4 py-3 text-right text-gray-600">{totalResources}</td>
                      <td className="px-4 py-3 text-right border-r">{totalFindings}</td>
                      <td className="px-4 py-3 text-right text-green-600 bg-green-50/50">{totalPassing}</td>
                      <td className="px-4 py-3 text-right text-red-600 bg-red-50/50">{totalFailing}</td>
                      <td className="px-4 py-3 text-right text-purple-600 bg-purple-50/50 border-r">{totalExceptions}</td>
                      <td className="px-4 py-3 text-right">
                        <span className={totalCritical > 0 ? 'text-red-600' : 'text-gray-400'}>{totalCritical}</span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className={totalHigh > 0 ? 'text-orange-600' : 'text-gray-400'}>{totalHigh}</span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className={totalMedium > 0 ? 'text-yellow-600' : 'text-gray-400'}>{totalMedium}</span>
                      </td>
                      <td className="px-4 py-3 text-right border-r">
                        <span className={totalLow > 0 ? 'text-blue-600' : 'text-gray-400'}>{totalLow}</span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className={
                          Number(overallCompliance) === 100 ? 'text-green-600' :
                          Number(overallCompliance) >= 80 ? 'text-yellow-600' : 'text-red-600'
                        }>
                          {overallCompliance}%
                        </span>
                      </td>
                    </tr>
                  )
                })()}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Workflow Status */}
      <div className="mt-6 bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold mb-4">Findings by Workflow Status</h2>
        <div className="grid grid-cols-5 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-600">
              {summaryData.by_workflow_status?.OPEN || 0}
            </div>
            <div className="text-sm text-gray-500">Open</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">
              {summaryData.by_workflow_status?.ACKNOWLEDGED || 0}
            </div>
            <div className="text-sm text-gray-500">Acknowledged</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">
              {summaryData.by_workflow_status?.PLANNED || 0}
            </div>
            <div className="text-sm text-gray-500">Planned</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-600">
              {summaryData.by_workflow_status?.IN_PROGRESS || 0}
            </div>
            <div className="text-sm text-gray-500">In Progress</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">
              {summaryData.by_workflow_status?.RESOLVED || 0}
            </div>
            <div className="text-sm text-gray-500">Resolved</div>
          </div>
        </div>
      </div>

      {/* Resources by Type */}
      {sortedResourceTypes.length > 0 && (
        <div className="mt-6 bg-white rounded-lg shadow p-6">
          <div className="flex items-center gap-2 mb-4">
            <Box className="w-5 h-5 text-gray-500" />
            <h2 className="text-lg font-semibold">Resources by Type</h2>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
            {sortedResourceTypes.map(([resourceType, data]: [string, any]) => (
              <div key={resourceType} className="border rounded-lg p-4 hover:bg-gray-50">
                <div className="text-sm font-medium text-gray-700 mb-2">{formatResourceType(resourceType)}</div>
                <div className="space-y-1 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Resources</span>
                    <span className="font-medium">{data.resource_count}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Findings</span>
                    <span className="font-medium">{data.finding_count}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Non-Compliant</span>
                    <span className={data.failing_count > 0 ? 'font-medium text-red-600' : 'text-gray-400'}>
                      {data.failing_count}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  )
}
