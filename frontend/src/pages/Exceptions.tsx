import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { useState } from 'react'
import { Trash2, Filter, X, Pencil } from 'lucide-react'
import { getExceptions, deleteException, updateException, bulkUpdateExceptions, getAccounts, getRules } from '../services/api'

export default function Exceptions() {
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [editingException, setEditingException] = useState<any | null>(null)
  const [showBulkEditModal, setShowBulkEditModal] = useState(false)
  const [editForm, setEditForm] = useState({
    justification: '',
    expires_at: '',
  })

  // Read filters from URL params
  const page = parseInt(searchParams.get('page') || '1', 10)
  const filters = {
    scope: searchParams.get('scope') || '',
    account_id: searchParams.get('account_id') || '',
    rule_id: searchParams.get('rule_id') || '',
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
      scope: newFilters.scope,
      account_id: newFilters.account_id,
      rule_id: newFilters.rule_id,
      page: '', // Reset page when filters change
    })
  }

  const { data: accountsData } = useQuery({
    queryKey: ['accounts'],
    queryFn: () => getAccounts(1, 100),
  })

  const { data: rulesData } = useQuery({
    queryKey: ['rules'],
    queryFn: () => getRules(1, 100),
  })

  const accounts = accountsData?.data?.items || []
  const rules = rulesData?.data?.items || []

  const activeFilterCount = Object.values(filters).filter(v => v !== '').length

  const clearFilters = () => {
    setSearchParams(new URLSearchParams())
  }

  const { data, isLoading } = useQuery({
    queryKey: ['exceptions', page, filters],
    queryFn: () => getExceptions({
      page,
      per_page: 50,
      ...(filters.scope && { scope: filters.scope }),
      ...(filters.account_id && { account_id: filters.account_id }),
      ...(filters.rule_id && { rule_id: filters.rule_id }),
    }),
  })

  const removeException = useMutation({
    mutationFn: (id: string) => deleteException(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exceptions'] })
    },
  })

  const updateExceptionMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { justification?: string; expires_at?: string | null } }) =>
      updateException(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exceptions'] })
      setEditingException(null)
      setEditForm({ justification: '', expires_at: '' })
    },
  })

  const bulkUpdateMutation = useMutation({
    mutationFn: (data: { exception_ids: string[]; justification?: string; expires_at?: string | null }) =>
      bulkUpdateExceptions(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exceptions'] })
      setShowBulkEditModal(false)
      setSelectedIds([])
      setEditForm({ justification: '', expires_at: '' })
    },
  })

  const exceptions = data?.data?.items || []
  const total = data?.data?.total || 0
  const pages = data?.data?.pages || 1

  const handleEditClick = (exc: any) => {
    setEditingException(exc)
    setEditForm({
      justification: exc.justification,
      expires_at: exc.expires_at ? exc.expires_at.split('T')[0] : '',
    })
  }

  const handleSaveEdit = () => {
    if (!editingException) return
    updateExceptionMutation.mutate({
      id: editingException.id,
      data: {
        justification: editForm.justification,
        expires_at: editForm.expires_at || null,
      },
    })
  }

  const handleBulkEdit = () => {
    setEditForm({ justification: '', expires_at: '' })
    setShowBulkEditModal(true)
  }

  const handleSaveBulkEdit = () => {
    const updateData: { exception_ids: string[]; justification?: string; expires_at?: string | null } = {
      exception_ids: selectedIds,
    }
    if (editForm.justification) {
      updateData.justification = editForm.justification
    }
    if (editForm.expires_at) {
      updateData.expires_at = editForm.expires_at
    }
    bulkUpdateMutation.mutate(updateData)
  }

  const toggleSelection = (id: string) => {
    setSelectedIds(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    )
  }

  const toggleSelectAll = () => {
    if (selectedIds.length === exceptions.length) {
      setSelectedIds([])
    } else {
      setSelectedIds(exceptions.map((e: any) => e.id))
    }
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Exceptions</h1>
        {selectedIds.length > 0 && (
          <button
            onClick={handleBulkEdit}
            className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            <Pencil className="w-4 h-4" />
            Edit {selectedIds.length} Selected
          </button>
        )}
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
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Scope</label>
            <select
              value={filters.scope}
              onChange={(e) => setFilters({ ...filters, scope: e.target.value })}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Scopes</option>
              <option value="RESOURCE">Resource</option>
              <option value="RULE">Rule</option>
              <option value="ACCOUNT">Account</option>
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
            <label className="block text-xs font-medium text-gray-500 mb-1">Rule</label>
            <select
              value={filters.rule_id}
              onChange={(e) => setFilters({ ...filters, rule_id: e.target.value })}
              className="w-full border rounded-lg px-3 py-2 text-sm"
            >
              <option value="">All Rules</option>
              {rules.map((rule: any) => (
                <option key={rule.id} value={rule.id}>
                  {rule.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <th className="px-4 py-3 w-10">
                <input
                  type="checkbox"
                  checked={exceptions.length > 0 && selectedIds.length === exceptions.length}
                  onChange={toggleSelectAll}
                  className="rounded border-gray-300"
                />
              </th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Scope</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Resource/Account</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Rule</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Justification</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Created By</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Created</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Expires</th>
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
            ) : exceptions.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-gray-500">
                  No exceptions found
                </td>
              </tr>
            ) : (
              exceptions.map((exc: any) => (
                <tr key={exc.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(exc.id)}
                      onChange={() => toggleSelection(exc.id)}
                      className="rounded border-gray-300"
                    />
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 rounded text-xs font-medium bg-gray-100">
                      {exc.scope}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {exc.resource_id || exc.account_id || '-'}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {exc.rule?.name || '-'}
                  </td>
                  <td className="px-4 py-3 text-sm max-w-xs truncate" title={exc.justification}>
                    {exc.justification}
                  </td>
                  <td className="px-4 py-3 text-sm">{exc.created_by}</td>
                  <td className="px-4 py-3 text-sm">
                    {exc.created_at
                      ? new Date(exc.created_at).toLocaleDateString()
                      : '-'}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {exc.expires_at
                      ? new Date(exc.expires_at).toLocaleDateString()
                      : 'Never'}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleEditClick(exc)}
                        className="text-blue-600 hover:text-blue-800"
                        title="Edit"
                      >
                        <Pencil className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => removeException.mutate(exc.id)}
                        className="text-red-600 hover:text-red-800"
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
            Showing {exceptions.length} of {total} exceptions
            {selectedIds.length > 0 && (
              <span className="ml-2 text-blue-600">({selectedIds.length} selected)</span>
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

      {/* Edit Modal */}
      {editingException && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg w-full max-w-md p-6">
            <h2 className="text-lg font-semibold mb-4">Edit Exception</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Justification
                </label>
                <textarea
                  value={editForm.justification}
                  onChange={(e) => setEditForm({ ...editForm, justification: e.target.value })}
                  rows={4}
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  placeholder="Enter justification..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Expires At
                </label>
                <input
                  type="date"
                  value={editForm.expires_at}
                  onChange={(e) => setEditForm({ ...editForm, expires_at: e.target.value })}
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                />
                <p className="text-xs text-gray-500 mt-1">Leave empty for no expiration</p>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => {
                  setEditingException(null)
                  setEditForm({ justification: '', expires_at: '' })
                }}
                className="px-4 py-2 border rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEdit}
                disabled={updateExceptionMutation.isPending}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {updateExceptionMutation.isPending ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Edit Modal */}
      {showBulkEditModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg w-full max-w-md p-6">
            <h2 className="text-lg font-semibold mb-4">
              Edit {selectedIds.length} Exception{selectedIds.length > 1 ? 's' : ''}
            </h2>
            <p className="text-sm text-gray-500 mb-4">
              Only filled fields will be updated. Leave a field empty to keep existing values.
            </p>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Justification
                </label>
                <textarea
                  value={editForm.justification}
                  onChange={(e) => setEditForm({ ...editForm, justification: e.target.value })}
                  rows={4}
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                  placeholder="Enter new justification for all selected..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Expires At
                </label>
                <input
                  type="date"
                  value={editForm.expires_at}
                  onChange={(e) => setEditForm({ ...editForm, expires_at: e.target.value })}
                  className="w-full border rounded-lg px-3 py-2 text-sm"
                />
                <p className="text-xs text-gray-500 mt-1">Set new expiration for all selected</p>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => {
                  setShowBulkEditModal(false)
                  setEditForm({ justification: '', expires_at: '' })
                }}
                className="px-4 py-2 border rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveBulkEdit}
                disabled={bulkUpdateMutation.isPending || (!editForm.justification && !editForm.expires_at)}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {bulkUpdateMutation.isPending ? 'Updating...' : 'Update All'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
