import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Plus, Trash2, CheckCircle, XCircle, Loader2, HelpCircle, X, Copy, Check, Pencil } from 'lucide-react'
import { getAccounts, createAccount, deleteAccount, testAccountConnection, updateAccount } from '../services/api'

interface AccountForm {
  name: string
  account_id: string
  role_arn: string
  external_id: string
  is_active?: boolean
}

function OnboardingModal({ onClose }: { onClose: () => void }) {
  const [copiedCode, setCopiedCode] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'local' | 'production'>('local')

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedCode(id)
    setTimeout(() => setCopiedCode(null), 2000)
  }

  const SECURITY_ACCOUNT_ID = '771834038176'

  const productionTrustPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${SECURITY_ACCOUNT_ID}:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "compliance-scanner-UNIQUE_ID"
        }
      }
    }
  ]
}`

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-white border-b px-6 py-4 flex justify-between items-center">
          <h2 className="text-xl font-bold">How to Onboard an AWS Account</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Tab Selector */}
        <div className="border-b px-6">
          <div className="flex gap-4">
            <button
              onClick={() => setActiveTab('local')}
              className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'local'
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Local Development (SSO)
            </button>
            <button
              onClick={() => setActiveTab('production')}
              className={`py-3 px-1 border-b-2 font-medium text-sm transition-colors ${
                activeTab === 'production'
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              Production Deployment
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {activeTab === 'local' ? (
            <>
              {/* Local Development Instructions */}
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <h3 className="font-semibold text-yellow-800 mb-2">Local Development with AWS SSO</h3>
                <p className="text-yellow-700 text-sm mb-2">
                  <strong>This setup mirrors production deployment.</strong> In production, the scanner runs in the Security account
                  and assumes roles in target accounts. Local development uses the same pattern via SSO.
                </p>
                <p className="text-yellow-700 text-sm">
                  You must have SSO access to the Security account (<code className="bg-yellow-100 px-1 rounded">{SECURITY_ACCOUNT_ID}</code>).
                  The scanner assumes a <code className="bg-yellow-100 px-1 rounded">ComplianceScanner</code> role in each target account.
                </p>
              </div>

              {/* AWS Config Setup */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                  <span className="bg-blue-600 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm">1</span>
                  Configure AWS Profile
                </h3>
                <p className="text-sm text-gray-700 mb-3">
                  Add this profile to <code className="bg-gray-100 px-1 rounded">~/.aws/config</code>:
                </p>
                <pre className="bg-gray-900 text-gray-100 p-3 rounded-lg text-xs overflow-x-auto">{`[profile compliance-scanner]
sso_session = your-sso-session
sso_account_id = ${SECURITY_ACCOUNT_ID}
sso_role_name = AdministratorAccess
region = us-east-2`}</pre>
              </div>

              {/* Prerequisites */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                  <span className="bg-blue-600 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm">2</span>
                  Prerequisites
                </h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-700 ml-4">
                  <li>Run <code className="bg-gray-100 px-1 rounded">aws sso login --profile compliance-scanner</code></li>
                  <li>Set <code className="bg-gray-100 px-1 rounded">AWS_PROFILE=compliance-scanner</code> in <code className="bg-gray-100 px-1 rounded">.env</code></li>
                  <li>Create <code className="bg-gray-100 px-1 rounded">ComplianceScanner</code> role in each target account (see below)</li>
                </ol>
              </div>

              {/* Create Role */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                  <span className="bg-blue-600 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm">2</span>
                  Create ComplianceScanner Role in Each Target Account
                </h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-700 ml-4">
                  <li>Go to IAM &gt; Roles &gt; Create role</li>
                  <li>Trusted entity: <strong>AWS account</strong> &gt; <strong>Another AWS account</strong></li>
                  <li>Account ID: <code className="bg-gray-100 px-1 rounded">{SECURITY_ACCOUNT_ID}</code> (Security account)</li>
                  <li>Attach policies: <code className="bg-gray-100 px-1 rounded">ReadOnlyAccess</code> + <code className="bg-gray-100 px-1 rounded">SecurityAudit</code></li>
                  <li>Role name: <code className="bg-gray-100 px-1 rounded">ComplianceScanner</code></li>
                </ol>
              </div>

              {/* Add Accounts */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                  <span className="bg-blue-600 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm">3</span>
                  Add Accounts to Scan
                </h3>
                <p className="text-sm text-gray-700 mb-3">
                  For each AWS account, click "Add Account" and enter:
                </p>
                <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="font-medium text-gray-700">Account Name:</span>
                      <p className="text-gray-500">Descriptive name (e.g., "Production", "Dev")</p>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Account ID:</span>
                      <p className="text-gray-500">12-digit AWS account ID</p>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">Role ARN:</span>
                      <p className="text-gray-500 font-mono text-xs">arn:aws:iam::ACCOUNT_ID:role/ComplianceScanner</p>
                    </div>
                    <div>
                      <span className="font-medium text-gray-700">External ID:</span>
                      <p className="text-gray-500">Leave empty (not needed for org accounts)</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Example */}
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <h3 className="font-semibold text-green-800 mb-3">Example: Adding Multiple Accounts</h3>
                <div className="space-y-2 text-sm font-mono">
                  <div className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    <span className="text-green-800">Dev | 586639910174 | arn:aws:iam::586639910174:role/ComplianceScanner</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    <span className="text-green-800">UAT | 225599959436 | arn:aws:iam::225599959436:role/ComplianceScanner</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Check className="w-4 h-4 text-green-600" />
                    <span className="text-green-800">Prod | 354543717275 | arn:aws:iam::354543717275:role/ComplianceScanner</span>
                  </div>
                </div>
              </div>

              {/* Troubleshooting */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3">Troubleshooting</h3>
                <ul className="space-y-2 text-sm text-gray-700">
                  <li><strong>Access Denied:</strong> Ensure <code className="bg-gray-100 px-1 rounded">ComplianceScanner</code> role trusts the Security account ({SECURITY_ACCOUNT_ID})</li>
                  <li><strong>Token Expired:</strong> Run <code className="bg-gray-100 px-1 rounded">aws sso login --profile compliance-scanner</code> again</li>
                  <li><strong>Role Not Found:</strong> Create the <code className="bg-gray-100 px-1 rounded">ComplianceScanner</code> role in the target account</li>
                </ul>
              </div>
            </>
          ) : (
            <>
              {/* Production Instructions */}
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h3 className="font-semibold text-blue-800 mb-2">Production Deployment</h3>
                <p className="text-blue-700 text-sm">
                  The scanner runs in the Security account (<code className="bg-blue-100 px-1 rounded">{SECURITY_ACCOUNT_ID}</code>)
                  and assumes a dedicated role in each target account. This requires creating an IAM role in each account.
                </p>
              </div>

              {/* Step 1 */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                  <span className="bg-blue-600 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm">1</span>
                  Create IAM Role in Target Account
                </h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-700 ml-4">
                  <li>Sign in to the AWS Console for the target account</li>
                  <li>Go to IAM &gt; Roles &gt; Create role</li>
                  <li>Select "AWS account" as the trusted entity type</li>
                  <li>Choose "Another AWS account" and enter: <code className="bg-gray-100 px-1 rounded">{SECURITY_ACCOUNT_ID}</code></li>
                  <li>Check "Require external ID" and enter a unique identifier</li>
                  <li>Click Next to add permissions</li>
                </ol>
              </div>

              {/* Step 2 - Trust Policy */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                  <span className="bg-blue-600 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm">2</span>
                  Configure Trust Policy
                </h3>
                <p className="text-sm text-gray-700 mb-3">
                  The role trusts the Security account. Replace <code className="bg-gray-100 px-1 rounded">UNIQUE_ID</code> with a unique identifier.
                </p>
                <div className="relative">
                  <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg text-sm overflow-x-auto">{productionTrustPolicy}</pre>
                  <button
                    onClick={() => copyToClipboard(productionTrustPolicy, 'trust')}
                    className="absolute top-2 right-2 bg-gray-700 hover:bg-gray-600 text-white p-2 rounded"
                  >
                    {copiedCode === 'trust' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Step 3 - Permissions */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                  <span className="bg-blue-600 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm">3</span>
                  Attach Permissions Policies
                </h3>
                <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                  <p className="text-sm text-green-800 mb-3">
                    <strong>Attach these AWS managed policies:</strong>
                  </p>
                  <ul className="space-y-2 text-sm text-green-800">
                    <li className="flex items-start gap-2">
                      <Check className="w-4 h-4 mt-0.5 flex-shrink-0" />
                      <div>
                        <code className="bg-green-100 px-1 rounded font-semibold">ReadOnlyAccess</code>
                        <span className="text-green-700 ml-1">(AWS managed - job function)</span>
                      </div>
                    </li>
                    <li className="flex items-start gap-2">
                      <Check className="w-4 h-4 mt-0.5 flex-shrink-0" />
                      <div>
                        <code className="bg-green-100 px-1 rounded font-semibold">SecurityAudit</code>
                        <span className="text-green-700 ml-1">(AWS managed - job function)</span>
                      </div>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Step 4 - Add to Scanner */}
              <div className="border rounded-lg p-4">
                <h3 className="font-semibold text-lg mb-3 flex items-center gap-2">
                  <span className="bg-blue-600 text-white w-6 h-6 rounded-full flex items-center justify-center text-sm">4</span>
                  Add Account to Scanner
                </h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-700 ml-4">
                  <li>Name the role (e.g., <code className="bg-gray-100 px-1 rounded">ComplianceScanner</code>) and create it</li>
                  <li>Click "Add Account" on this page</li>
                  <li>Enter the account details:
                    <ul className="list-disc list-inside ml-4 mt-1 space-y-1">
                      <li>Account Name: Descriptive name</li>
                      <li>Account ID: 12-digit AWS account ID</li>
                      <li>Role ARN: <code className="bg-gray-100 px-1 rounded text-xs">arn:aws:iam::ACCOUNT_ID:role/ComplianceScanner</code></li>
                      <li>External ID: The unique ID you chose in step 2</li>
                    </ul>
                  </li>
                  <li>Click "Test" to verify the connection works</li>
                </ol>
              </div>
            </>
          )}
        </div>

        <div className="sticky bottom-0 bg-gray-50 border-t px-6 py-4">
          <button
            onClick={onClose}
            className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700"
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Accounts() {
  const [showForm, setShowForm] = useState(false)
  const [showOnboarding, setShowOnboarding] = useState(false)
  const [editingAccount, setEditingAccount] = useState<any>(null)
  const [form, setForm] = useState<AccountForm>({
    name: '',
    account_id: '',
    role_arn: '',
    external_id: '',
  })
  const [testingAccount, setTestingAccount] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, boolean>>({})
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => getAccounts(),
  })

  const addAccount = useMutation({
    mutationFn: createAccount,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['accounts'] })
      setShowForm(false)
      setForm({ name: '', account_id: '', role_arn: '', external_id: '' })
    },
    onError: (error: any) => {
      console.error('Failed to create account:', error.response?.data || error.message)
      alert(error.response?.data?.detail || 'Failed to create account')
    },
  })

  const editAccount = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<AccountForm> }) =>
      updateAccount(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['accounts'] })
      setEditingAccount(null)
      setShowForm(false)
      setForm({ name: '', account_id: '', role_arn: '', external_id: '' })
    },
    onError: (error: any) => {
      console.error('Failed to update account:', error.response?.data || error.message)
      alert(error.response?.data?.detail || 'Failed to update account')
    },
  })

  const removeAccount = useMutation({
    mutationFn: deleteAccount,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['accounts'] })
    },
  })

  const handleTestConnection = async (accountId: string) => {
    setTestingAccount(accountId)
    try {
      const result = await testAccountConnection(accountId)
      setTestResults(prev => ({ ...prev, [accountId]: result.data.success }))
    } catch {
      setTestResults(prev => ({ ...prev, [accountId]: false }))
    } finally {
      setTestingAccount(null)
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (editingAccount) {
      editAccount.mutate({
        id: editingAccount.id,
        data: {
          name: form.name,
          role_arn: form.role_arn || '',
          external_id: form.external_id || '',
          is_active: form.is_active,
        }
      })
    } else {
      addAccount.mutate(form)
    }
  }

  const handleEdit = (account: any) => {
    setEditingAccount(account)
    setForm({
      name: account.name,
      account_id: account.account_id,
      role_arn: account.role_arn || '',
      external_id: account.external_id || '',
      is_active: account.is_active,
    })
    setShowForm(true)
  }

  const handleCancelEdit = () => {
    setShowForm(false)
    setEditingAccount(null)
    setForm({ name: '', account_id: '', role_arn: '', external_id: '' })
  }

  const accounts = data?.data?.items || []

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">AWS Accounts</h1>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowOnboarding(true)}
            className="flex items-center gap-2 border border-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-50"
          >
            <HelpCircle className="w-4 h-4" />
            How to Onboard
          </button>
          <button
            onClick={() => setShowForm(true)}
            className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
          >
            <Plus className="w-4 h-4" />
            Add Account
          </button>
        </div>
      </div>

      {showOnboarding && <OnboardingModal onClose={() => setShowOnboarding(false)} />}

      {showForm && (
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">
            {editingAccount ? 'Edit AWS Account' : 'Add AWS Account'}
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Account Name
                </label>
                <input
                  type="text"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full border rounded px-3 py-2"
                  placeholder="Production Account"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  AWS Account ID
                </label>
                <input
                  type="text"
                  value={form.account_id}
                  onChange={e => setForm(f => ({ ...f, account_id: e.target.value }))}
                  className="w-full border rounded px-3 py-2 disabled:bg-gray-100 disabled:cursor-not-allowed"
                  placeholder="123456789012"
                  required
                  disabled={!!editingAccount}
                />
                {editingAccount && (
                  <p className="text-xs text-gray-500 mt-1">
                    Account ID cannot be changed
                  </p>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Role ARN
                </label>
                <input
                  type="text"
                  value={form.role_arn}
                  onChange={e => setForm(f => ({ ...f, role_arn: e.target.value }))}
                  className="w-full border rounded px-3 py-2"
                  placeholder="arn:aws:iam::123456789012:role/ComplianceScanner"
                />
                <p className="text-xs text-gray-500 mt-1">
                  Leave empty to use default credentials
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  External ID
                </label>
                <input
                  type="text"
                  value={form.external_id}
                  onChange={e => setForm(f => ({ ...f, external_id: e.target.value }))}
                  className="w-full border rounded px-3 py-2"
                  placeholder="Optional external ID"
                />
              </div>
              {editingAccount && (
                <div className="col-span-2">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={form.is_active !== false}
                      onChange={e => setForm(f => ({ ...f, is_active: e.target.checked }))}
                      className="rounded"
                    />
                    <span className="text-sm font-medium text-gray-700">Account is active</span>
                  </label>
                  <p className="text-xs text-gray-500 mt-1 ml-6">
                    Inactive accounts will not be included in scans
                  </p>
                </div>
              )}
            </div>
            <div className="flex gap-2">
              <button
                type="submit"
                disabled={addAccount.isPending || editAccount.isPending}
                className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 disabled:opacity-50"
              >
                {(addAccount.isPending || editAccount.isPending)
                  ? 'Saving...'
                  : editingAccount
                  ? 'Update Account'
                  : 'Add Account'}
              </button>
              <button
                type="button"
                onClick={handleCancelEdit}
                className="border px-4 py-2 rounded hover:bg-gray-50"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Name</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Account ID</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Role ARN</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Status</th>
              <th className="text-center px-4 py-3 text-sm font-medium text-gray-500">Edit</th>
              <th className="text-center px-4 py-3 text-sm font-medium text-gray-500">Test</th>
              <th className="text-center px-4 py-3 text-sm font-medium text-gray-500">Delete</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  Loading...
                </td>
              </tr>
            ) : accounts.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                  No accounts configured. Add an AWS account to start scanning.
                </td>
              </tr>
            ) : (
              accounts.map((account: any) => (
                <tr key={account.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="font-medium">{account.name}</div>
                  </td>
                  <td className="px-4 py-3 text-sm font-mono">{account.account_id}</td>
                  <td className="px-4 py-3 text-sm font-mono truncate max-w-xs">
                    {account.role_arn || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`px-2 py-1 rounded text-xs font-medium ${
                        account.is_active
                          ? 'bg-green-100 text-green-800'
                          : 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {account.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <button
                      onClick={() => handleEdit(account)}
                      className="text-blue-600 hover:text-blue-800"
                      title="Edit account"
                    >
                      <Pencil className="w-4 h-4 inline" />
                    </button>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <button
                      onClick={() => handleTestConnection(account.id)}
                      disabled={testingAccount === account.id}
                      className="text-blue-600 hover:text-blue-800 disabled:opacity-50"
                      title="Test connection"
                    >
                      {testingAccount === account.id ? (
                        <Loader2 className="w-4 h-4 animate-spin inline" />
                      ) : testResults[account.id] === true ? (
                        <CheckCircle className="w-4 h-4 text-green-600 inline" />
                      ) : testResults[account.id] === false ? (
                        <XCircle className="w-4 h-4 text-red-600 inline" />
                      ) : (
                        <CheckCircle className="w-4 h-4 inline" />
                      )}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <button
                      onClick={() => removeAccount.mutate(account.id)}
                      className="text-red-600 hover:text-red-800"
                      title="Delete account"
                    >
                      <Trash2 className="w-4 h-4 inline" />
                    </button>
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
