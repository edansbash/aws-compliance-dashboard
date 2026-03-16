import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, RefreshCw, ShieldOff, Wrench, X, Loader2, Play, CheckCircle, ExternalLink, Ticket } from 'lucide-react'
import { formatDateTime } from '../utils/dateTime'
import { getFinding, updateFindingWorkflow, rescanFinding, createException, previewRemediation, createRemediationJob, getJiraConfig, createJiraTicketForFinding } from '../services/api'
import { useState, useEffect } from 'react'
import { clsx } from 'clsx'
import JsonDiff from '../components/JsonDiff'

function RemediationPreviewModal({
  finding,
  onClose,
  onSuccess
}: {
  finding: any
  onClose: () => void
  onSuccess: () => void
}) {
  const [preview, setPreview] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [executing, setExecuting] = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    const fetchPreview = async () => {
      try {
        const response = await previewRemediation({ finding_ids: [finding.id] })
        setPreview(response.data.findings[0])
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to load preview')
      } finally {
        setLoading(false)
      }
    }
    fetchPreview()
  }, [finding.id])

  const handleExecute = async () => {
    setExecuting(true)
    setError('')
    try {
      await createRemediationJob({
        finding_ids: [finding.id],
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
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[80vh] flex flex-col">
        <div className="flex justify-between items-center px-6 py-4 border-b">
          <h2 className="text-xl font-bold">Remediation Preview</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <X className="w-6 h-6" />
          </button>
        </div>

        <div className="px-6 py-4 overflow-y-auto flex-1">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
            </div>
          ) : success ? (
            <div className="bg-green-50 border border-green-200 rounded-lg p-6 flex flex-col items-center gap-4">
              <CheckCircle className="w-12 h-12 text-green-600" />
              <div className="text-center">
                <p className="font-semibold text-green-800 text-lg">Remediation Job Queued</p>
                <p className="text-sm text-green-700 mt-2">
                  The remediation job has been created successfully.
                </p>
                <p className="text-sm text-green-700">
                  View progress on the Remediation page.
                </p>
              </div>
            </div>
          ) : error ? (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          ) : preview && preview.can_remediate ? (
            <div className="space-y-4">
              <div>
                <h3 className="font-medium text-gray-700 mb-1">Resource</h3>
                <p className="text-sm font-mono">{preview.resource_id}</p>
                <p className="text-sm text-gray-600">{preview.resource_name}</p>
              </div>

              <div>
                <h3 className="font-medium text-gray-700 mb-1">Rule</h3>
                <p className="text-sm">{preview.rule_name}</p>
              </div>

              <div>
                <h3 className="font-medium text-gray-700 mb-1">Planned Action</h3>
                {preview.planned_action?.includes('WARNING:') ? (
                  <div className="space-y-3">
                    <p className="text-sm">{preview.planned_action.split('WARNING:')[0].trim()}</p>
                    <div className="bg-red-600 text-white rounded-lg p-3 shadow-md">
                      <div className="flex items-start gap-2">
                        <span className="text-xl">⚠️</span>
                        <div>
                          <p className="font-bold text-sm">WARNING</p>
                          <p className="text-sm mt-1">{preview.planned_action.split('WARNING:')[1].trim()}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-sm">{preview.planned_action}</p>
                )}
              </div>

              {preview.preview && (
                <div>
                  <h3 className="font-medium text-gray-700 mb-2">Changes</h3>
                  <JsonDiff
                    before={preview.preview.before}
                    after={preview.preview.after}
                  />
                </div>
              )}

              <div className="bg-yellow-50 border border-yellow-200 rounded p-4">
                <p className="text-sm text-yellow-800">
                  ⚠️ This action will modify your AWS resources. Please review the changes carefully before proceeding.
                </p>
              </div>
            </div>
          ) : (
            <div className="bg-gray-50 border border-gray-200 text-gray-700 px-4 py-3 rounded">
              {preview?.reason || 'Remediation not available for this finding'}
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t flex gap-3">
          {success ? (
            <>
              <button
                onClick={onClose}
                className="flex-1 px-4 py-2 border rounded-lg hover:bg-gray-50"
              >
                Close
              </button>
              <button
                onClick={handleViewJobs}
                className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                View Remediation Page
              </button>
            </>
          ) : (
            <>
              <button
                onClick={onClose}
                className="flex-1 px-4 py-2 border rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleExecute}
                disabled={loading || executing || !preview?.can_remediate}
                className="flex-1 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 flex items-center justify-center gap-2"
              >
                {executing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Executing...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    Confirm & Execute
                  </>
                )}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function CreateExceptionModal({
  finding,
  onClose,
  onSuccess
}: {
  finding: any
  onClose: () => void
  onSuccess: () => void
}) {
  const [justification, setJustification] = useState('')
  const [scope, setScope] = useState('RESOURCE')
  const [expiresAt, setExpiresAt] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    setError('')

    try {
      await createException({
        rule_id: finding.rule.id,
        resource_id: scope === 'RESOURCE' ? finding.resource_id : undefined,
        account_id: scope === 'ACCOUNT' ? finding.account_id : undefined,
        scope,
        justification,
        created_by: 'user',
        expires_at: expiresAt || undefined,
      })
      onSuccess()
      onClose()
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create exception')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-lg w-full">
        <div className="flex justify-between items-center px-6 py-4 border-b">
          <h2 className="text-xl font-bold">Create Exception</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <X className="w-6 h-6" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Exception Scope
            </label>
            <select
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              className="w-full border rounded-lg px-3 py-2"
            >
              <option value="RESOURCE">This Resource Only</option>
              <option value="RULE">All Resources for This Rule</option>
              <option value="ACCOUNT">All Resources in This Account</option>
            </select>
            <p className="text-xs text-gray-500 mt-1">
              {scope === 'RESOURCE' && `Exception applies to: ${finding.resource_id}`}
              {scope === 'RULE' && `Exception applies to rule: ${finding.rule?.name}`}
              {scope === 'ACCOUNT' && `Exception applies to account: ${finding.account_id}`}
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Justification <span className="text-red-500">*</span>
            </label>
            <textarea
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              className="w-full border rounded-lg px-3 py-2 h-24"
              placeholder="Explain why this exception is needed..."
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Expires At (Optional)
            </label>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              className="w-full border rounded-lg px-3 py-2"
            />
            <p className="text-xs text-gray-500 mt-1">
              Leave empty for permanent exception
            </p>
          </div>

          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !justification}
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {isSubmitting ? 'Creating...' : 'Create Exception'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function FindingDetail() {
  const { id } = useParams()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [notes, setNotes] = useState('')
  const [showExceptionModal, setShowExceptionModal] = useState(false)
  const [showRemediationModal, setShowRemediationModal] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['finding', id],
    queryFn: () => getFinding(id!),
    enabled: !!id,
  })

  const { data: jiraConfig } = useQuery({
    queryKey: ['jira-config'],
    queryFn: getJiraConfig,
  })

  const updateWorkflow = useMutation({
    mutationFn: (workflow_status: string) =>
      updateFindingWorkflow(id!, { workflow_status, notes, updated_by: 'user' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', id] })
    },
  })

  const rescan = useMutation({
    mutationFn: () => rescanFinding(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', id] })
    },
  })

  const createJiraTicket = useMutation({
    mutationFn: () => createJiraTicketForFinding(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', id] })
    },
  })

  const finding = data?.data

  if (isLoading) {
    return <div className="p-6">Loading...</div>
  }

  if (!finding) {
    return <div className="p-6">Finding not found</div>
  }

  return (
    <div>
      <button onClick={() => navigate(-1)} className="flex items-center gap-2 text-gray-600 hover:text-gray-800 mb-4">
        <ArrowLeft className="w-4 h-4" />
        Back to Findings
      </button>

      <div className="flex justify-between items-start mb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">{finding.resource_name}</h1>
            {finding.details?.tags?.ManagedBy?.toLowerCase() === 'terraform' && (
              <span className="inline-flex items-center gap-1 px-3 py-1 bg-purple-100 text-purple-800 text-sm font-medium rounded-full">
                Terraform
              </span>
            )}
          </div>
          <p className="text-gray-500">{finding.resource_id}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => rescan.mutate()}
            disabled={rescan.isPending}
            className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-gray-50"
          >
            <RefreshCw className={clsx('w-4 h-4', rescan.isPending && 'animate-spin')} />
            Rescan
          </button>
          <button
            onClick={() => setShowExceptionModal(true)}
            className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-gray-50"
          >
            <ShieldOff className="w-4 h-4" />
            Create Exception
          </button>
          {jiraConfig?.data?.is_enabled && !finding.jira_ticket_key && (
            <button
              onClick={() => createJiraTicket.mutate()}
              disabled={createJiraTicket.isPending}
              className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-gray-50 disabled:opacity-50"
            >
              <Ticket className={clsx('w-4 h-4', createJiraTicket.isPending && 'animate-pulse')} />
              {createJiraTicket.isPending ? 'Creating...' : 'Create Ticket'}
            </button>
          )}
          {finding.rule?.has_remediation && finding.status === 'FAIL' && (
            <button
              onClick={() => setShowRemediationModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700"
            >
              <Wrench className="w-4 h-4" />
              Remediate
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Info */}
        <div className="col-span-2 space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Finding Details</h2>
            <dl className="grid grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-gray-500">Status</dt>
                <dd className="font-medium">{finding.status}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Workflow Status</dt>
                <dd className="font-medium">{finding.workflow_status}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Account ID</dt>
                <dd className="font-medium">{finding.account_id}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Region</dt>
                <dd className="font-medium">{finding.region}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Resource Type</dt>
                <dd className="font-medium">{finding.resource_type}</dd>
              </div>
              <div>
                <dt className="text-sm text-gray-500">Discovered</dt>
                <dd className="font-medium">{formatDateTime(finding.created_at)}</dd>
              </div>
              {finding.jira_ticket_key && jiraConfig?.data?.base_url && (
                <div>
                  <dt className="text-sm text-gray-500">JIRA Ticket</dt>
                  <dd>
                    <a
                      href={`${jiraConfig.data.base_url}/browse/${finding.jira_ticket_key}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800 font-medium"
                    >
                      {finding.jira_ticket_key}
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </dd>
                </div>
              )}
            </dl>
          </div>

          {/* Rule Info */}
          {finding.rule && (
            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-lg font-semibold mb-4">Rule Information</h2>
              <dl className="space-y-3">
                <div>
                  <dt className="text-sm text-gray-500">Rule Name</dt>
                  <dd className="font-medium">{finding.rule.name}</dd>
                </div>
                <div>
                  <dt className="text-sm text-gray-500">Description</dt>
                  <dd className="text-gray-700">{finding.rule.description}</dd>
                </div>
                <div>
                  <dt className="text-sm text-gray-500">Severity</dt>
                  <dd className="font-medium">{finding.rule.severity}</dd>
                </div>
              </dl>
            </div>
          )}

          {/* Details */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Resource Details</h2>
            <pre className="bg-gray-50 p-4 rounded overflow-auto text-sm">
              {JSON.stringify(finding.details, null, 2)}
            </pre>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Workflow Status */}
          <div className="bg-white rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold mb-4">Update Workflow</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-gray-500 mb-1">Status</label>
                <select
                  value={finding.workflow_status}
                  onChange={(e) => updateWorkflow.mutate(e.target.value)}
                  className="w-full border rounded-lg px-3 py-2"
                >
                  <option value="OPEN">Open</option>
                  <option value="ACKNOWLEDGED">Acknowledged</option>
                  <option value="PLANNED">Planned</option>
                  <option value="IN_PROGRESS">In Progress</option>
                  <option value="RESOLVED">Resolved</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-gray-500 mb-1">Notes</label>
                <textarea
                  value={notes || finding.workflow_notes || ''}
                  onChange={(e) => setNotes(e.target.value)}
                  className="w-full border rounded-lg px-3 py-2 h-24"
                  placeholder="Add notes about remediation progress..."
                />
                <button
                  onClick={() => updateWorkflow.mutate(finding.workflow_status)}
                  disabled={updateWorkflow.isPending || (!notes && !finding.workflow_notes)}
                  className="mt-2 w-full px-3 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-50"
                >
                  {updateWorkflow.isPending ? 'Saving...' : 'Save Notes'}
                </button>
              </div>
              {finding.workflow_updated_at && (
                <div className="text-sm text-gray-500">
                  Last updated: {formatDateTime(finding.workflow_updated_at)}
                  {finding.workflow_updated_by && ` by ${finding.workflow_updated_by}`}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {showExceptionModal && (
        <CreateExceptionModal
          finding={finding}
          onClose={() => setShowExceptionModal(false)}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ['finding', id] })
            queryClient.invalidateQueries({ queryKey: ['exceptions'] })
          }}
        />
      )}

      {showRemediationModal && (
        <RemediationPreviewModal
          finding={finding}
          onClose={() => setShowRemediationModal(false)}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ['finding', id] })
            queryClient.invalidateQueries({ queryKey: ['findings'] })
          }}
        />
      )}
    </div>
  )
}
