import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  Play, CheckCircle, XCircle, Clock, Loader2, ChevronDown, StopCircle,
  Plus, Pencil, Trash2, Calendar, ToggleLeft, ToggleRight
} from 'lucide-react'
import {
  getScans, createScan, getAccounts, cancelScan,
  getScheduledScans, createScheduledScan, updateScheduledScan,
  deleteScheduledScan, runScheduledScan, enableScheduledScan, disableScheduledScan
} from '../services/api'
import { clsx } from 'clsx'
import { formatDateTime } from '../utils/dateTime'

const US_REGIONS = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']

// Common cron presets for easy selection
const CRON_PRESETS = [
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Daily at 2 AM', value: '0 2 * * *' },
  { label: 'Daily at 6 AM', value: '0 6 * * *' },
  { label: 'Weekdays at 9 AM', value: '0 9 * * 1-5' },
  { label: 'Weekly (Sunday 2 AM)', value: '0 2 * * 0' },
  { label: 'Monthly (1st at 2 AM)', value: '0 2 1 * *' },
]

interface ScheduledScanForm {
  name: string
  description: string
  account_ids: string[]
  regions: string[]
  schedule_type: 'cron' | 'interval'
  schedule_expression: string
  timezone: string
  enabled: boolean
}

const initialFormState: ScheduledScanForm = {
  name: '',
  description: '',
  account_ids: [],
  regions: [...US_REGIONS],
  schedule_type: 'cron',
  schedule_expression: '0 2 * * *',
  timezone: 'UTC',
  enabled: true,
}

export default function Scans() {
  const [activeTab, setActiveTab] = useState<'history' | 'scheduled'>('history')
  const [page, setPage] = useState(1)
  const [scheduledPage, setScheduledPage] = useState(1)
  const [showScanOptions, setShowScanOptions] = useState(false)
  const [selectedAccounts, setSelectedAccounts] = useState<string[]>([])
  const [selectedRegions, setSelectedRegions] = useState<string[]>([...US_REGIONS])

  // Scheduled scan modal state
  const [showScheduleModal, setShowScheduleModal] = useState(false)
  const [editingSchedule, setEditingSchedule] = useState<any>(null)
  const [scheduleForm, setScheduleForm] = useState<ScheduledScanForm>(initialFormState)
  const [usePreset, setUsePreset] = useState(true)

  const queryClient = useQueryClient()

  // Fetch scan history
  const { data, isLoading } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => getScans(page, 20),
    refetchInterval: 5000,
  })

  // Fetch scheduled scans
  const { data: scheduledData, isLoading: scheduledLoading } = useQuery({
    queryKey: ['scheduled-scans', scheduledPage],
    queryFn: () => getScheduledScans(scheduledPage, 20),
    refetchInterval: 10000,
  })

  const { data: accountsData } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => getAccounts(1, 100),
  })

  const accounts = accountsData?.data?.items || []

  const accountMap = accounts.reduce((acc: Record<string, any>, account: any) => {
    acc[account.id] = account
    return acc
  }, {})

  const getAccountsDisplay = (scanAccountIds: string[] | null) => {
    if (!scanAccountIds || scanAccountIds.length === 0) {
      return <span className="text-gray-400">All accounts</span>
    }
    const resolvedAccounts = scanAccountIds
      .map(id => accountMap[id])
      .filter(Boolean)

    if (resolvedAccounts.length === 0) {
      return <span className="text-gray-400">{scanAccountIds.length} account(s)</span>
    }

    if (resolvedAccounts.length <= 2) {
      return (
        <div className="flex flex-col gap-0.5">
          {resolvedAccounts.map((acc: any) => (
            <span key={acc.id} className="text-xs">
              {acc.name} <span className="text-gray-400">({acc.account_id})</span>
            </span>
          ))}
        </div>
      )
    }

    return (
      <span className="text-xs" title={resolvedAccounts.map((a: any) => `${a.name} (${a.account_id})`).join(', ')}>
        {resolvedAccounts.length} accounts
      </span>
    )
  }

  // Mutations
  const startScan = useMutation({
    mutationFn: () => createScan({
      account_ids: selectedAccounts.length > 0 ? selectedAccounts : undefined,
      regions: selectedRegions.length > 0 ? selectedRegions : undefined,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setShowScanOptions(false)
      setSelectedAccounts([])
      setSelectedRegions([...US_REGIONS])
    },
  })

  const cancelScanMutation = useMutation({
    mutationFn: (scanId: string) => cancelScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const createScheduleMutation = useMutation({
    mutationFn: (data: ScheduledScanForm) => createScheduledScan({
      ...data,
      account_ids: data.account_ids.length > 0 ? data.account_ids : undefined,
      regions: data.regions.length > 0 ? data.regions : undefined,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] })
      closeScheduleModal()
    },
    onError: (error: any) => {
      alert(error.response?.data?.detail || 'Failed to create schedule')
    },
  })

  const updateScheduleMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ScheduledScanForm> }) =>
      updateScheduledScan(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] })
      closeScheduleModal()
    },
    onError: (error: any) => {
      alert(error.response?.data?.detail || 'Failed to update schedule')
    },
  })

  const deleteScheduleMutation = useMutation({
    mutationFn: (id: string) => deleteScheduledScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] })
    },
  })

  const runNowMutation = useMutation({
    mutationFn: (id: string) => runScheduledScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] })
    },
  })

  const toggleEnableMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? disableScheduledScan(id) : enableScheduledScan(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] })
    },
  })

  // Helper functions
  const toggleAccount = (accountId: string) => {
    setSelectedAccounts(prev =>
      prev.includes(accountId)
        ? prev.filter(id => id !== accountId)
        : [...prev, accountId]
    )
  }

  const selectAllAccounts = () => {
    if (selectedAccounts.length === accounts.length) {
      setSelectedAccounts([])
    } else {
      setSelectedAccounts(accounts.map((a: any) => a.id))
    }
  }

  const toggleRegion = (region: string) => {
    setSelectedRegions((prev: string[]) =>
      prev.includes(region)
        ? prev.filter((r: string) => r !== region)
        : [...prev, region]
    )
  }

  const selectAllRegions = () => {
    if (selectedRegions.length === US_REGIONS.length) {
      setSelectedRegions([])
    } else {
      setSelectedRegions([...US_REGIONS])
    }
  }

  const toggleFormAccount = (accountId: string) => {
    setScheduleForm(prev => ({
      ...prev,
      account_ids: prev.account_ids.includes(accountId)
        ? prev.account_ids.filter(id => id !== accountId)
        : [...prev.account_ids, accountId]
    }))
  }

  const toggleFormRegion = (region: string) => {
    setScheduleForm(prev => ({
      ...prev,
      regions: prev.regions.includes(region)
        ? prev.regions.filter(r => r !== region)
        : [...prev.regions, region]
    }))
  }

  const openCreateModal = () => {
    setEditingSchedule(null)
    setScheduleForm(initialFormState)
    setUsePreset(true)
    setShowScheduleModal(true)
  }

  const openEditModal = (schedule: any) => {
    setEditingSchedule(schedule)
    setScheduleForm({
      name: schedule.name,
      description: schedule.description || '',
      account_ids: schedule.account_ids || [],
      regions: schedule.regions || [],
      schedule_type: schedule.schedule_type,
      schedule_expression: schedule.schedule_expression,
      timezone: schedule.timezone || 'UTC',
      enabled: schedule.enabled,
    })
    setUsePreset(CRON_PRESETS.some(p => p.value === schedule.schedule_expression))
    setShowScheduleModal(true)
  }

  const closeScheduleModal = () => {
    setShowScheduleModal(false)
    setEditingSchedule(null)
    setScheduleForm(initialFormState)
  }

  const handleScheduleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (editingSchedule) {
      updateScheduleMutation.mutate({ id: editingSchedule.id, data: scheduleForm })
    } else {
      createScheduleMutation.mutate(scheduleForm)
    }
  }

  const scans = data?.data?.items || []
  const total = data?.data?.total || 0
  const pages = data?.data?.pages || 1

  const scheduledScans = scheduledData?.data?.items || []
  const scheduledTotal = scheduledData?.data?.total || 0
  const scheduledPages = scheduledData?.data?.pages || 1

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

  const formatSchedule = (schedule: any) => {
    if (schedule.schedule_type === 'interval') {
      const mins = parseInt(schedule.schedule_expression)
      if (mins >= 1440) return `Every ${Math.floor(mins / 1440)} day(s)`
      if (mins >= 60) return `Every ${Math.floor(mins / 60)} hour(s)`
      return `Every ${mins} minutes`
    }
    // Find matching preset
    const preset = CRON_PRESETS.find(p => p.value === schedule.schedule_expression)
    if (preset) return preset.label
    return schedule.schedule_expression
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Scans</h1>

        {activeTab === 'history' ? (
          <div className="relative">
            <button
              onClick={() => setShowScanOptions(!showScanOptions)}
              className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
            >
              <Play className="w-4 h-4" />
              New Scan
              <ChevronDown className={clsx('w-4 h-4 transition-transform', showScanOptions && 'rotate-180')} />
            </button>

            {showScanOptions && (
              <div className="absolute right-0 mt-2 w-80 bg-white rounded-lg shadow-lg border z-10">
                <div className="p-4">
                  <div className="flex justify-between items-center mb-3">
                    <span className="font-medium text-gray-700">Select Accounts</span>
                    <button
                      onClick={selectAllAccounts}
                      className="text-sm text-blue-600 hover:text-blue-800"
                    >
                      {selectedAccounts.length === accounts.length ? 'Deselect All' : 'Select All'}
                    </button>
                  </div>
                  <div className="max-h-32 overflow-y-auto space-y-2 mb-4">
                    {accounts.length === 0 ? (
                      <p className="text-sm text-gray-500">No accounts configured</p>
                    ) : (
                      accounts.map((account: any) => (
                        <label key={account.id} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={selectedAccounts.includes(account.id)}
                            onChange={() => toggleAccount(account.id)}
                            className="rounded border-gray-300"
                          />
                          <span className="text-sm">{account.name}</span>
                          <span className="text-xs text-gray-400">({account.account_id})</span>
                        </label>
                      ))
                    )}
                  </div>

                  <div className="flex justify-between items-center mb-3">
                    <span className="font-medium text-gray-700">Select Regions</span>
                    <button
                      onClick={selectAllRegions}
                      className="text-sm text-blue-600 hover:text-blue-800"
                    >
                      {selectedRegions.length === US_REGIONS.length ? 'Deselect All' : 'Select All'}
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-2 mb-4">
                    {US_REGIONS.map((region) => (
                      <label key={region} className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedRegions.includes(region)}
                          onChange={() => toggleRegion(region)}
                          className="rounded border-gray-300"
                        />
                        <span className="text-sm">{region}</span>
                      </label>
                    ))}
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => startScan.mutate()}
                      disabled={startScan.isPending || selectedRegions.length === 0}
                      className="flex-1 bg-blue-600 text-white px-3 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 text-sm"
                    >
                      {startScan.isPending ? 'Starting...' : 'Scan'}
                    </button>
                    <button
                      onClick={() => {
                        setShowScanOptions(false)
                        setSelectedAccounts([])
                      }}
                      className="px-3 py-2 border rounded-lg hover:bg-gray-50 text-sm"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          <button
            onClick={openCreateModal}
            className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            <Plus className="w-4 h-4" />
            New Schedule
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b mb-6">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('history')}
            className={clsx(
              'pb-3 px-1 border-b-2 font-medium text-sm transition-colors',
              activeTab === 'history'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            Scan History
          </button>
          <button
            onClick={() => setActiveTab('scheduled')}
            className={clsx(
              'pb-3 px-1 border-b-2 font-medium text-sm transition-colors flex items-center gap-2',
              activeTab === 'scheduled'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            )}
          >
            <Calendar className="w-4 h-4" />
            Scheduled Scans
            {scheduledScans.filter((s: any) => s.enabled).length > 0 && (
              <span className="bg-blue-100 text-blue-700 text-xs px-2 py-0.5 rounded-full">
                {scheduledScans.filter((s: any) => s.enabled).length}
              </span>
            )}
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'history' ? (
        /* Scan History Table */
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 border-b">
              <tr>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Status</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Started</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Completed</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Accounts</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Regions</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Resource Types</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Results</th>
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
              ) : scans.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                    No scans yet. Click "New Scan" to start.
                  </td>
                </tr>
              ) : (
                scans.map((scan: any) => (
                  <tr key={scan.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {getStatusIcon(scan.status)}
                        <span>{scan.status}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {formatDateTime(scan.started_at)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {formatDateTime(scan.completed_at)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {getAccountsDisplay(scan.account_ids)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {scan.regions?.join(', ') || '-'}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {scan.resource_types && scan.resource_types.length > 0 ? (
                        scan.resource_types.length <= 3 ? (
                          <div className="flex flex-col gap-0.5">
                            {scan.resource_types.map((type: string) => (
                              <span key={type} className="text-xs">{type.replace('AWS::', '')}</span>
                            ))}
                          </div>
                        ) : (
                          <span
                            className="text-xs cursor-help"
                            title={scan.resource_types.map((t: string) => t.replace('AWS::', '')).join(', ')}
                          >
                            {scan.resource_types.length} resource types
                          </span>
                        )
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {scan.status === 'RUNNING' ? (
                        <span className="text-gray-400">Scanning...</span>
                      ) : scan.status === 'COMPLETED' ? (
                        <div className="flex items-center gap-3">
                          <span className="text-green-600">
                            {scan.total_resources - scan.total_findings} passed
                          </span>
                          <span className={clsx(
                            scan.total_findings > 0 ? 'text-red-600 font-medium' : 'text-gray-400'
                          )}>
                            {scan.total_findings} failed
                          </span>
                          <span className="text-gray-400 text-xs">
                            ({scan.total_resources} checks)
                          </span>
                        </div>
                      ) : (
                        <span className="text-gray-400">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {(scan.status === 'RUNNING' || scan.status === 'PENDING' || scan.status === 'QUEUED') && (
                        <button
                          onClick={() => cancelScanMutation.mutate(scan.id)}
                          disabled={cancelScanMutation.isPending}
                          className="flex items-center gap-1 text-red-600 hover:text-red-800 disabled:opacity-50"
                          title="Cancel scan"
                        >
                          <StopCircle className="w-4 h-4" />
                          Cancel
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          <div className="px-4 py-3 border-t flex items-center justify-between">
            <div className="text-sm text-gray-500">
              Showing {scans.length} of {total} scans
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 border rounded disabled:opacity-50"
              >
                Previous
              </button>
              <span className="px-3 py-1">Page {page} of {pages}</span>
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
      ) : (
        /* Scheduled Scans Table */
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 border-b">
              <tr>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Status</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Name</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Schedule</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Accounts</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Regions</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Last Run</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Next Run</th>
                <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {scheduledLoading ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                    Loading...
                  </td>
                </tr>
              ) : scheduledScans.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                    No scheduled scans configured. Click "New Schedule" to create one.
                  </td>
                </tr>
              ) : (
                scheduledScans.map((schedule: any) => (
                  <tr key={schedule.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleEnableMutation.mutate({ id: schedule.id, enabled: schedule.enabled })}
                        disabled={toggleEnableMutation.isPending}
                        className="flex items-center gap-2"
                        title={schedule.enabled ? 'Click to disable' : 'Click to enable'}
                      >
                        {schedule.enabled ? (
                          <ToggleRight className="w-6 h-6 text-green-500" />
                        ) : (
                          <ToggleLeft className="w-6 h-6 text-gray-400" />
                        )}
                        <span className={schedule.enabled ? 'text-green-600' : 'text-gray-400'}>
                          {schedule.enabled ? 'Active' : 'Disabled'}
                        </span>
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <div>
                        <div className="font-medium">{schedule.name}</div>
                        {schedule.description && (
                          <div className="text-xs text-gray-500">{schedule.description}</div>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <div className="flex flex-col">
                        <span>{formatSchedule(schedule)}</span>
                        <span className="text-xs text-gray-400">{schedule.timezone}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {getAccountsDisplay(schedule.account_ids)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {schedule.regions?.length > 0
                        ? schedule.regions.join(', ')
                        : <span className="text-gray-400">Default regions</span>}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {schedule.last_run_at
                        ? formatDateTime(schedule.last_run_at)
                        : <span className="text-gray-400">Never</span>}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {schedule.enabled && schedule.next_run_at
                        ? formatDateTime(schedule.next_run_at)
                        : <span className="text-gray-400">-</span>}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => runNowMutation.mutate(schedule.id)}
                          disabled={runNowMutation.isPending}
                          className="p-1 text-blue-600 hover:text-blue-800 disabled:opacity-50"
                          title="Run now"
                        >
                          <Play className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openEditModal(schedule)}
                          className="p-1 text-gray-600 hover:text-gray-800"
                          title="Edit"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => {
                            if (confirm('Delete this scheduled scan?')) {
                              deleteScheduleMutation.mutate(schedule.id)
                            }
                          }}
                          disabled={deleteScheduleMutation.isPending}
                          className="p-1 text-red-600 hover:text-red-800 disabled:opacity-50"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>

          <div className="px-4 py-3 border-t flex items-center justify-between">
            <div className="text-sm text-gray-500">
              Showing {scheduledScans.length} of {scheduledTotal} schedules
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setScheduledPage(p => Math.max(1, p - 1))}
                disabled={scheduledPage === 1}
                className="px-3 py-1 border rounded disabled:opacity-50"
              >
                Previous
              </button>
              <span className="px-3 py-1">Page {scheduledPage} of {scheduledPages}</span>
              <button
                onClick={() => setScheduledPage(p => Math.min(scheduledPages, p + 1))}
                disabled={scheduledPage === scheduledPages}
                className="px-3 py-1 border rounded disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Schedule Modal */}
      {showScheduleModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <h2 className="text-xl font-bold mb-4">
                {editingSchedule ? 'Edit Scheduled Scan' : 'Create Scheduled Scan'}
              </h2>

              <form onSubmit={handleScheduleSubmit} className="space-y-4">
                {/* Name */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Name *
                  </label>
                  <input
                    type="text"
                    value={scheduleForm.name}
                    onChange={e => setScheduleForm(f => ({ ...f, name: e.target.value }))}
                    className="w-full border rounded-lg px-3 py-2"
                    placeholder="e.g., Nightly Compliance Scan"
                    required
                  />
                </div>

                {/* Description */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Description
                  </label>
                  <input
                    type="text"
                    value={scheduleForm.description}
                    onChange={e => setScheduleForm(f => ({ ...f, description: e.target.value }))}
                    className="w-full border rounded-lg px-3 py-2"
                    placeholder="Optional description"
                  />
                </div>

                {/* Schedule Type */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Schedule *
                  </label>
                  <div className="space-y-2">
                    <div className="flex gap-4">
                      <label className="flex items-center gap-2">
                        <input
                          type="radio"
                          checked={usePreset}
                          onChange={() => setUsePreset(true)}
                        />
                        <span className="text-sm">Use preset</span>
                      </label>
                      <label className="flex items-center gap-2">
                        <input
                          type="radio"
                          checked={!usePreset}
                          onChange={() => setUsePreset(false)}
                        />
                        <span className="text-sm">Custom cron</span>
                      </label>
                    </div>

                    {usePreset ? (
                      <select
                        value={scheduleForm.schedule_expression}
                        onChange={e => setScheduleForm(f => ({
                          ...f,
                          schedule_expression: e.target.value,
                          schedule_type: 'cron'
                        }))}
                        className="w-full border rounded-lg px-3 py-2"
                      >
                        {CRON_PRESETS.map(preset => (
                          <option key={preset.value} value={preset.value}>
                            {preset.label}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type="text"
                        value={scheduleForm.schedule_expression}
                        onChange={e => setScheduleForm(f => ({
                          ...f,
                          schedule_expression: e.target.value,
                          schedule_type: 'cron'
                        }))}
                        className="w-full border rounded-lg px-3 py-2 font-mono"
                        placeholder="0 2 * * *"
                      />
                    )}
                    <p className="text-xs text-gray-500">
                      Cron format: minute hour day month day_of_week (e.g., "0 2 * * *" = daily at 2 AM)
                    </p>
                  </div>
                </div>

                {/* Timezone */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Timezone
                  </label>
                  <select
                    value={scheduleForm.timezone}
                    onChange={e => setScheduleForm(f => ({ ...f, timezone: e.target.value }))}
                    className="w-full border rounded-lg px-3 py-2"
                  >
                    <option value="UTC">UTC</option>
                    <option value="US/Eastern">US/Eastern</option>
                    <option value="US/Central">US/Central</option>
                    <option value="US/Mountain">US/Mountain</option>
                    <option value="US/Pacific">US/Pacific</option>
                    <option value="Europe/London">Europe/London</option>
                    <option value="Europe/Paris">Europe/Paris</option>
                    <option value="Asia/Tokyo">Asia/Tokyo</option>
                  </select>
                </div>

                {/* Accounts */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Accounts
                  </label>
                  <div className="max-h-32 overflow-y-auto border rounded-lg p-2 space-y-1">
                    {accounts.length === 0 ? (
                      <p className="text-sm text-gray-500">No accounts configured</p>
                    ) : (
                      accounts.map((account: any) => (
                        <label key={account.id} className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={scheduleForm.account_ids.includes(account.id)}
                            onChange={() => toggleFormAccount(account.id)}
                            className="rounded border-gray-300"
                          />
                          <span className="text-sm">{account.name}</span>
                          <span className="text-xs text-gray-400">({account.account_id})</span>
                        </label>
                      ))
                    )}
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Leave empty to scan all active accounts
                  </p>
                </div>

                {/* Regions */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Regions
                  </label>
                  <div className="grid grid-cols-2 gap-2 border rounded-lg p-2">
                    {US_REGIONS.map(region => (
                      <label key={region} className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={scheduleForm.regions.includes(region)}
                          onChange={() => toggleFormRegion(region)}
                          className="rounded border-gray-300"
                        />
                        <span className="text-sm">{region}</span>
                      </label>
                    ))}
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Leave empty to use default scan regions
                  </p>
                </div>

                {/* Enabled */}
                <div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={scheduleForm.enabled}
                      onChange={e => setScheduleForm(f => ({ ...f, enabled: e.target.checked }))}
                      className="rounded border-gray-300"
                    />
                    <span className="text-sm font-medium text-gray-700">Enabled</span>
                  </label>
                </div>

                {/* Actions */}
                <div className="flex gap-2 pt-4">
                  <button
                    type="submit"
                    disabled={createScheduleMutation.isPending || updateScheduleMutation.isPending}
                    className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
                  >
                    {createScheduleMutation.isPending || updateScheduleMutation.isPending
                      ? 'Saving...'
                      : editingSchedule ? 'Update Schedule' : 'Create Schedule'}
                  </button>
                  <button
                    type="button"
                    onClick={closeScheduleModal}
                    className="px-4 py-2 border rounded-lg hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
