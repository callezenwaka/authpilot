import { onUnmounted } from 'vue'
import { apiKey } from '../auth'

export type SSEEvent = 'users' | 'groups' | 'flows' | 'sessions'

/**
 * Opens a single SSE connection to /api/v1/events and calls the matching
 * handler whenever the server fires an event. Closes on component unmount.
 */
export function useSSE(handlers: Partial<Record<SSEEvent, () => void>>): void {
  if (!apiKey) return

  const url = `/api/v1/events?api_key=${encodeURIComponent(apiKey)}`
  const es = new EventSource(url)

  for (const [event, handler] of Object.entries(handlers) as [SSEEvent, () => void][]) {
    es.addEventListener(event, handler)
  }

  onUnmounted(() => es.close())
}
