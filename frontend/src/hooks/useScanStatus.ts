/**
 * useScanStatus - Custom hook for real-time scan status updates via SSE
 *
 * This hook creates an EventSource connection to the backend SSE endpoint
 * and provides real-time scan status updates without polling.
 *
 * How SSE (Server-Sent Events) works:
 * 1. Client opens a persistent HTTP connection to the server
 * 2. Server keeps the connection open and pushes events when data changes
 * 3. Client receives events via the onmessage callback
 * 4. Connection closes automatically when scan completes or on error
 *
 * Benefits over polling:
 * - No repeated HTTP requests (single connection)
 * - Real-time updates (typically <10ms latency)
 * - Lower server load
 * - Automatic reconnection on disconnect
 */

import { useState, useEffect, useCallback, useRef } from 'react'

export interface ScanStatusEvent {
  type: 'status' | 'log' | 'complete'
  status?: string
  message?: string
  progress?: {
    current?: number
    total?: number
    percentage?: number
  }
  level?: string
  timestamp?: string
  total_resources?: number
  total_findings?: number
  error_message?: string
}

interface UseScanStatusOptions {
  /** Called when scan completes successfully */
  onComplete?: (event: ScanStatusEvent) => void
  /** Called when scan fails */
  onError?: (event: ScanStatusEvent) => void
  /** Called on any status update */
  onStatusChange?: (event: ScanStatusEvent) => void
}

interface UseScanStatusReturn {
  /** Current scan status (QUEUED, RUNNING, COMPLETED, FAILED) */
  status: string | null
  /** Whether the SSE connection is active */
  isConnected: boolean
  /** Most recent status message */
  message: string | null
  /** Log messages received during scan */
  logs: ScanStatusEvent[]
  /** Final scan results (when complete) */
  results: { total_resources: number; total_findings: number } | null
  /** Error message if scan failed */
  error: string | null
  /** Start listening to a scan */
  subscribe: (scanId: string) => void
  /** Stop listening and close connection */
  unsubscribe: () => void
}

export function useScanStatus(options: UseScanStatusOptions = {}): UseScanStatusReturn {
  const { onComplete, onError, onStatusChange } = options

  // State
  const [status, setStatus] = useState<string | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [logs, setLogs] = useState<ScanStatusEvent[]>([])
  const [results, setResults] = useState<{ total_resources: number; total_findings: number } | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Ref to hold the EventSource instance
  // Using ref so we can access it in cleanup without re-renders
  const eventSourceRef = useRef<EventSource | null>(null)

  /**
   * Close existing EventSource connection if any
   */
  const closeConnection = useCallback(() => {
    if (eventSourceRef.current) {
      console.log('[SSE] Closing connection')
      eventSourceRef.current.close()
      eventSourceRef.current = null
      setIsConnected(false)
    }
  }, [])

  /**
   * Subscribe to scan status updates for a specific scan
   *
   * @param scanId - UUID of the scan to monitor
   */
  const subscribe = useCallback((scanId: string) => {
    // Close any existing connection first
    closeConnection()

    // Reset state for new subscription
    setStatus(null)
    setMessage(null)
    setLogs([])
    setResults(null)
    setError(null)

    // Create new EventSource connection
    // EventSource is a browser API that handles SSE connections
    // Use full API URL since there's no proxy configured for SSE
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000'
    const url = `${apiUrl}/api/v1/scans/${scanId}/status/stream`
    console.log(`[SSE] Connecting to ${url}`)

    const eventSource = new EventSource(url)
    eventSourceRef.current = eventSource

    /**
     * Called when connection is established
     */
    eventSource.onopen = () => {
      console.log('[SSE] Connection opened')
      setIsConnected(true)
    }

    /**
     * Called when a message is received from the server
     * Each message is a JSON-encoded event with type and data
     */
    eventSource.onmessage = (event) => {
      try {
        const data: ScanStatusEvent = JSON.parse(event.data)
        console.log('[SSE] Received event:', data)

        // Handle different event types
        switch (data.type) {
          case 'status':
            // Status update (QUEUED, RUNNING, etc.)
            setStatus(data.status || null)
            setMessage(data.message || null)
            onStatusChange?.(data)
            break

          case 'log':
            // Progress log message
            setLogs((prev) => [...prev, data])
            setMessage(data.message || null)
            break

          case 'complete':
            // Scan finished (success or failure)
            setStatus(data.status || null)
            setResults({
              total_resources: data.total_resources || 0,
              total_findings: data.total_findings || 0,
            })

            if (data.status === 'COMPLETED') {
              onComplete?.(data)
            } else if (data.status === 'FAILED') {
              setError(data.error_message || 'Scan failed')
              onError?.(data)
            }

            // Close connection - scan is done
            closeConnection()
            break
        }
      } catch (err) {
        console.error('[SSE] Failed to parse event:', err)
      }
    }

    /**
     * Called when connection encounters an error
     * EventSource automatically tries to reconnect on errors
     */
    eventSource.onerror = (err) => {
      console.error('[SSE] Connection error:', err)

      // Check if this is a final close or a temporary error
      if (eventSource.readyState === EventSource.CLOSED) {
        setIsConnected(false)
        // Don't set error here - could be normal close after completion
      }
    }
  }, [closeConnection, onComplete, onError, onStatusChange])

  /**
   * Unsubscribe from updates and close connection
   */
  const unsubscribe = useCallback(() => {
    closeConnection()
    setStatus(null)
    setMessage(null)
    setLogs([])
    setResults(null)
    setError(null)
  }, [closeConnection])

  /**
   * Cleanup on unmount - close any open connection
   */
  useEffect(() => {
    return () => {
      closeConnection()
    }
  }, [closeConnection])

  return {
    status,
    isConnected,
    message,
    logs,
    results,
    error,
    subscribe,
    unsubscribe,
  }
}
