/**
 * JsonDiff component - displays changes between before/after states.
 * Handles different scenarios: modifications, deletions, and creations.
 */

interface JsonDiffProps {
  before: Record<string, any>
  after: Record<string, any>
  className?: string
}

function formatJsonValue(value: any, indent: number = 0): string {
  if (value === null) return 'null'
  if (value === undefined) return 'undefined'
  if (typeof value === 'string') return `"${value}"`
  if (typeof value === 'boolean' || typeof value === 'number') return String(value)
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]'
    return JSON.stringify(value, null, 2)
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value)
    if (keys.length === 0) return '{}'
    return JSON.stringify(value, null, 2)
  }
  return String(value)
}

// Fields to exclude from diff display (internal/metadata fields)
const excludedFields = new Set(['message'])

// Priority ordering for common fields (lower = higher priority)
const fieldPriority: Record<string, number> = {
  // Identity fields first
  'resource_id': 1,
  'resource_name': 2,
  'name': 3,
  'id': 4,
  'security_group_id': 5,
  'security_group_name': 6,
  'bucket_name': 7,
  'vpc_id': 10,
  'account_id': 11,
  'region': 12,

  // Status/state fields
  'status': 20,
  'is_enabled': 21,
  'is_used': 22,
  'is_unused': 23,
  'is_default': 24,

  // Configuration fields
  'versioning_enabled': 30,
  'encryption_enabled': 31,
  'encryption_type': 32,
  'policy': 40,
  'bucket_policy': 41,

  // Rules/permissions
  'inbound_rules': 50,
  'inbound_rules_count': 51,
  'outbound_rules': 52,
  'outbound_rules_count': 53,

  // Metadata
  'description': 60,
  'tags': 70,
  'message': 80,

  // Attachments last
  'attached_resources': 90,
  'attached_resource_count': 91,
}

function sortKeys(keys: string[]): string[] {
  return [...keys].sort((a, b) => {
    const priorityA = fieldPriority[a] ?? 100
    const priorityB = fieldPriority[b] ?? 100
    if (priorityA !== priorityB) return priorityA - priorityB
    return a.localeCompare(b)
  })
}

export default function JsonDiff({ before, after, className = '' }: JsonDiffProps) {
  const beforeKeys = Object.keys(before)
  const afterKeys = Object.keys(after)

  // Detect scenario
  const isDeletion = beforeKeys.length > 0 && afterKeys.length === 0
  const isCreation = beforeKeys.length === 0 && afterKeys.length > 0

  // For deletions (like removing a security group), show a simple summary
  if (isDeletion) {
    // Pick key identifying fields to show
    const identityFields = ['security_group_name', 'security_group_id', 'bucket_name', 'resource_name', 'name', 'id']
    const shownFields = identityFields.filter(f => f in before)

    return (
      <div className={`rounded border border-red-300 overflow-hidden ${className}`}>
        <div className="bg-red-100 px-3 py-2 border-b border-red-300">
          <span className="text-red-800 font-medium text-sm">Resource will be deleted</span>
        </div>
        <div className="bg-red-50 p-3 font-mono text-xs">
          {shownFields.length > 0 ? (
            <div className="space-y-1">
              {shownFields.map(key => (
                <div key={key} className="text-red-700">
                  <span className="text-red-500">{key}:</span> {formatJsonValue(before[key])}
                </div>
              ))}
            </div>
          ) : (
            <span className="text-red-600">All resource data will be removed</span>
          )}
        </div>
      </div>
    )
  }

  // For modifications, show only changed fields (excluding internal metadata fields)
  const allKeys = sortKeys(Array.from(new Set([...beforeKeys, ...afterKeys])))
    .filter(key => !excludedFields.has(key))

  const changes: Array<{
    key: string
    type: 'added' | 'removed' | 'changed'
    oldValue?: any
    newValue?: any
  }> = []

  for (const key of allKeys) {
    const hasOld = key in before
    const hasNew = key in after

    if (!hasOld && hasNew) {
      changes.push({ key, type: 'added', newValue: after[key] })
    } else if (hasOld && !hasNew) {
      changes.push({ key, type: 'removed', oldValue: before[key] })
    } else if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) {
      changes.push({ key, type: 'changed', oldValue: before[key], newValue: after[key] })
    }
  }

  if (changes.length === 0) {
    return (
      <div className={`bg-gray-50 border border-gray-200 rounded p-3 ${className}`}>
        <p className="text-sm text-gray-500 italic">No changes detected</p>
      </div>
    )
  }

  return (
    <div className={`rounded border border-gray-300 overflow-hidden ${className}`}>
      <div className="bg-gray-100 px-3 py-2 border-b border-gray-300">
        <span className="text-gray-700 font-medium text-sm">Changes ({changes.length} field{changes.length !== 1 ? 's' : ''})</span>
      </div>
      <div className="divide-y divide-gray-200">
        {changes.map(change => (
          <div key={change.key} className="px-3 py-2">
            <div className="font-mono text-xs">
              <span className="text-gray-600 font-medium">{change.key}</span>
            </div>
            {change.type === 'added' && (
              <div className="mt-1 font-mono text-xs">
                <span className="inline-block bg-green-100 text-green-800 px-2 py-0.5 rounded">
                  + {formatJsonValue(change.newValue)}
                </span>
              </div>
            )}
            {change.type === 'removed' && (
              <div className="mt-1 font-mono text-xs">
                <span className="inline-block bg-red-100 text-red-800 px-2 py-0.5 rounded line-through">
                  {formatJsonValue(change.oldValue)}
                </span>
              </div>
            )}
            {change.type === 'changed' && (
              <div className="mt-1 font-mono text-xs flex items-center gap-2 flex-wrap">
                <span className="inline-block bg-red-100 text-red-700 px-2 py-0.5 rounded">
                  {formatJsonValue(change.oldValue)}
                </span>
                <span className="text-gray-400">→</span>
                <span className="inline-block bg-green-100 text-green-700 px-2 py-0.5 rounded">
                  {formatJsonValue(change.newValue)}
                </span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
