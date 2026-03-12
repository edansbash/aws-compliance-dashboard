import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { useState } from 'react'
import { Plus, Package, ExternalLink, Trash2 } from 'lucide-react'
import { getCompliancePacks, createCompliancePack, updateCompliancePack, deleteCompliancePack } from '../services/api'
import { clsx } from 'clsx'

export default function CompliancePacks() {
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newPackName, setNewPackName] = useState('')
  const [newPackDescription, setNewPackDescription] = useState('')
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['compliance-packs'],
    queryFn: () => getCompliancePacks(1, 100),
  })

  const createMutation = useMutation({
    mutationFn: (data: { name: string; description?: string }) => createCompliancePack(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-packs'] })
      setShowCreateModal(false)
      setNewPackName('')
      setNewPackDescription('')
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, is_enabled }: { id: string; is_enabled: boolean }) =>
      updateCompliancePack(id, { is_enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-packs'] })
      queryClient.invalidateQueries({ queryKey: ['rules'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteCompliancePack(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-packs'] })
    },
  })

  const packs = data?.data?.items || []

  const handleCreate = () => {
    if (newPackName.trim()) {
      createMutation.mutate({
        name: newPackName.trim(),
        description: newPackDescription.trim() || undefined,
      })
    }
  }

  const handleDelete = (id: string, name: string) => {
    if (confirm(`Are you sure you want to delete "${name}"?`)) {
      deleteMutation.mutate(id)
    }
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Compliance Packs</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          <Plus className="w-4 h-4" />
          New Pack
        </button>
      </div>

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50 border-b">
            <tr>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Enabled</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Name</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Description</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Rules</th>
              <th className="text-left px-4 py-3 text-sm font-medium text-gray-500">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {isLoading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  Loading...
                </td>
              </tr>
            ) : packs.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                  <div className="flex flex-col items-center gap-2">
                    <Package className="w-8 h-8 text-gray-400" />
                    <p>No compliance packs yet</p>
                    <p className="text-sm">Create a pack to group rules together</p>
                  </div>
                </td>
              </tr>
            ) : (
              packs.map((pack: any) => (
                <tr key={pack.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleMutation.mutate({
                        id: pack.id,
                        is_enabled: !pack.is_enabled,
                      })}
                      className={clsx(
                        'w-10 h-6 rounded-full relative transition-colors',
                        pack.is_enabled ? 'bg-blue-600' : 'bg-gray-300'
                      )}
                    >
                      <span
                        className={clsx(
                          'absolute top-1 w-4 h-4 bg-white rounded-full transition-transform',
                          pack.is_enabled ? 'left-5' : 'left-1'
                        )}
                      />
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/compliance-packs/${pack.id}`}
                      className="font-medium text-blue-600 hover:text-blue-800 hover:underline"
                    >
                      {pack.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">
                    {pack.description || '-'}
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/compliance-packs/${pack.id}`}
                      className="text-blue-600 hover:text-blue-800 flex items-center gap-1"
                    >
                      {pack.rule_count} rules
                      <ExternalLink className="w-3 h-3" />
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleDelete(pack.id, pack.name)}
                      className="text-red-600 hover:text-red-800 p-1"
                      title="Delete pack"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg w-full max-w-md p-6">
            <h2 className="text-xl font-semibold mb-4">Create Compliance Pack</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Name
                </label>
                <input
                  type="text"
                  value={newPackName}
                  onChange={(e) => setNewPackName(e.target.value)}
                  className="w-full border rounded-lg px-3 py-2"
                  placeholder="e.g., CIS AWS Foundations"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Description (optional)
                </label>
                <textarea
                  value={newPackDescription}
                  onChange={(e) => setNewPackDescription(e.target.value)}
                  className="w-full border rounded-lg px-3 py-2"
                  rows={3}
                  placeholder="Describe this compliance pack..."
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button
                onClick={() => {
                  setShowCreateModal(false)
                  setNewPackName('')
                  setNewPackDescription('')
                }}
                className="px-4 py-2 border rounded-lg hover:bg-gray-50"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={!newPackName.trim() || createMutation.isPending}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
              >
                {createMutation.isPending ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
