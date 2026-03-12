import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { FileText, Download, Trash2, FileSpreadsheet, Loader2 } from 'lucide-react'
import { clsx } from 'clsx'
import {
  getReports,
  getScans,
  getAccounts,
  generateDashboardPdf,
  generateFindingsExcel,
  downloadReport,
  deleteReport,
} from '../services/api'

type ReportType = 'DASHBOARD_PDF' | 'FINDINGS_EXCEL'

export default function Reports() {
  const queryClient = useQueryClient()
  const [isGenerating, setIsGenerating] = useState<ReportType | null>(null)
  const [filters, setFilters] = useState({
    scan_id: '',
    account_ids: [] as string[],
    severities: [] as string[],
    statuses: [] as string[],
  })

  const { data: reports, isLoading: reportsLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => getReports(1, 50),
  })

  const { data: scans } = useQuery({
    queryKey: ['scans'],
    queryFn: () => getScans(1, 20),
  })

  const { data: accounts } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => getAccounts(1, 100),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteReport(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
    },
  })

  const handleGeneratePdf = async () => {
    setIsGenerating('DASHBOARD_PDF')
    try {
      const params: Record<string, string> = {}
      if (filters.scan_id) params.scan_id = filters.scan_id
      if (filters.account_ids.length) params.account_ids = filters.account_ids.join(',')
      if (filters.severities.length) params.severities = filters.severities.join(',')

      const response = await generateDashboardPdf(params)

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `compliance_dashboard_${new Date().toISOString().slice(0,10)}.pdf`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

      queryClient.invalidateQueries({ queryKey: ['reports'] })
    } catch (error) {
      console.error('Failed to generate PDF:', error)
      alert('Failed to generate PDF report')
    } finally {
      setIsGenerating(null)
    }
  }

  const handleGenerateExcel = async () => {
    setIsGenerating('FINDINGS_EXCEL')
    try {
      const params: Record<string, string> = {}
      if (filters.scan_id) params.scan_id = filters.scan_id
      if (filters.account_ids.length) params.account_ids = filters.account_ids.join(',')
      if (filters.severities.length) params.severities = filters.severities.join(',')
      if (filters.statuses.length) params.statuses = filters.statuses.join(',')

      const response = await generateFindingsExcel(params)

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `compliance_findings_${new Date().toISOString().slice(0,10)}.xlsx`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

      queryClient.invalidateQueries({ queryKey: ['reports'] })
    } catch (error) {
      console.error('Failed to generate Excel:', error)
      alert('Failed to generate Excel report')
    } finally {
      setIsGenerating(null)
    }
  }

  const handleDownload = async (report: any) => {
    try {
      const response = await downloadReport(report.id)
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      const ext = report.format === 'PDF' ? 'pdf' : 'xlsx'
      link.setAttribute('download', `report_${report.id.slice(0, 8)}.${ext}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to download report:', error)
      alert('Failed to download report')
    }
  }

  const toggleSeverity = (severity: string) => {
    setFilters(f => ({
      ...f,
      severities: f.severities.includes(severity)
        ? f.severities.filter(s => s !== severity)
        : [...f.severities, severity]
    }))
  }

  const toggleStatus = (status: string) => {
    setFilters(f => ({
      ...f,
      statuses: f.statuses.includes(status)
        ? f.statuses.filter(s => s !== status)
        : [...f.statuses, status]
    }))
  }

  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Reports</h1>

      {/* Report Generator */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <h2 className="text-lg font-semibold mb-4">Generate Report</h2>

        {/* Filters */}
        <div className="grid grid-cols-2 gap-6 mb-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Scan (Optional)
            </label>
            <select
              value={filters.scan_id}
              onChange={(e) => setFilters(f => ({ ...f, scan_id: e.target.value }))}
              className="w-full border border-gray-300 rounded-lg px-3 py-2"
            >
              <option value="">All Scans (Latest Data)</option>
              {scans?.data?.items?.map((scan: any) => (
                <option key={scan.id} value={scan.id}>
                  {new Date(scan.created_at).toLocaleString()} - {scan.status}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Account (Optional)
            </label>
            <select
              value={filters.account_ids[0] || ''}
              onChange={(e) => setFilters(f => ({
                ...f,
                account_ids: e.target.value ? [e.target.value] : []
              }))}
              className="w-full border border-gray-300 rounded-lg px-3 py-2"
            >
              <option value="">All Accounts</option>
              {accounts?.data?.items?.map((account: any) => (
                <option key={account.id} value={account.account_id}>
                  {account.name} ({account.account_id})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Severity Filter */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Severity Filter
          </label>
          <div className="flex gap-2">
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => (
              <button
                key={severity}
                onClick={() => toggleSeverity(severity)}
                className={clsx(
                  'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                  filters.severities.includes(severity)
                    ? severity === 'CRITICAL' ? 'bg-red-600 text-white' :
                      severity === 'HIGH' ? 'bg-orange-500 text-white' :
                      severity === 'MEDIUM' ? 'bg-yellow-500 text-white' :
                      'bg-blue-500 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                )}
              >
                {severity}
              </button>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-1">
            {filters.severities.length === 0 ? 'All severities included' : `Filtering: ${filters.severities.join(', ')}`}
          </p>
        </div>

        {/* Status Filter (for Excel only) */}
        <div className="mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Status Filter (Excel only)
          </label>
          <div className="flex gap-2">
            {['PASS', 'FAIL', 'EXCEPTION'].map((status) => (
              <button
                key={status}
                onClick={() => toggleStatus(status)}
                className={clsx(
                  'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                  filters.statuses.includes(status)
                    ? status === 'PASS' ? 'bg-green-600 text-white' :
                      status === 'FAIL' ? 'bg-red-600 text-white' :
                      'bg-violet-600 text-white'
                    : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                )}
              >
                {status}
              </button>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-1">
            {filters.statuses.length === 0 ? 'All statuses included' : `Filtering: ${filters.statuses.join(', ')}`}
          </p>
        </div>

        {/* Generate Buttons */}
        <div className="flex gap-4">
          <button
            onClick={handleGeneratePdf}
            disabled={isGenerating !== null}
            className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            {isGenerating === 'DASHBOARD_PDF' ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              <FileText className="w-5 h-5" />
            )}
            {isGenerating === 'DASHBOARD_PDF' ? 'Generating...' : 'Generate Dashboard PDF'}
          </button>

          <button
            onClick={handleGenerateExcel}
            disabled={isGenerating !== null}
            className="flex items-center gap-2 bg-green-600 text-white px-4 py-2 rounded-lg hover:bg-green-700 disabled:opacity-50"
          >
            {isGenerating === 'FINDINGS_EXCEL' ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              <FileSpreadsheet className="w-5 h-5" />
            )}
            {isGenerating === 'FINDINGS_EXCEL' ? 'Generating...' : 'Export Findings to Excel'}
          </button>
        </div>
      </div>

      {/* Report History */}
      <div className="bg-white rounded-lg shadow">
        <div className="p-4 border-b">
          <h2 className="text-lg font-semibold">Report History</h2>
        </div>

        {reportsLoading ? (
          <div className="p-8 text-center text-gray-500">Loading...</div>
        ) : reports?.data?.items?.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No reports generated yet. Use the form above to create your first report.
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Type</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Format</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Size</th>
                <th className="px-4 py-3 text-left text-sm font-medium text-gray-500">Created</th>
                <th className="px-4 py-3 text-right text-sm font-medium text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {reports?.data?.items?.map((report: any) => (
                <tr key={report.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {report.format === 'PDF' ? (
                        <FileText className="w-5 h-5 text-red-500" />
                      ) : (
                        <FileSpreadsheet className="w-5 h-5 text-green-500" />
                      )}
                      <span className="font-medium">
                        {report.report_type === 'DASHBOARD_PDF' ? 'Dashboard Report' : 'Findings Export'}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-gray-600">{report.format}</td>
                  <td className="px-4 py-3">
                    <span className={clsx(
                      'px-2 py-1 rounded-full text-xs font-medium',
                      report.status === 'COMPLETED' ? 'bg-green-100 text-green-700' :
                      report.status === 'FAILED' ? 'bg-red-100 text-red-700' :
                      'bg-yellow-100 text-yellow-700'
                    )}>
                      {report.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-600">
                    {report.file_size ? `${(report.file_size / 1024).toFixed(1)} KB` : '-'}
                  </td>
                  <td className="px-4 py-3 text-gray-600">
                    {new Date(report.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      {report.status === 'COMPLETED' && (
                        <button
                          onClick={() => handleDownload(report)}
                          className="p-2 text-blue-600 hover:bg-blue-50 rounded"
                          title="Download"
                        >
                          <Download className="w-4 h-4" />
                        </button>
                      )}
                      <button
                        onClick={() => {
                          if (confirm('Delete this report?')) {
                            deleteMutation.mutate(report.id)
                          }
                        }}
                        className="p-2 text-red-600 hover:bg-red-50 rounded"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
