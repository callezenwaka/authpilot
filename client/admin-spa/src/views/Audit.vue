<template>
  <div class="page">
    <div class="page-header">
      <h1>Audit Log</h1>
      <button class="btn btn-ghost btn-sm" @click="load">Refresh</button>
    </div>

    <!-- Filters -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-body" style="padding:14px 18px">
        <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
          <div class="form-group" style="margin:0;flex:1;min-width:160px">
            <label>Event type</label>
            <select v-model="filterType" @change="load">
              <option value="">All types</option>
              <option v-for="t in knownTypes" :key="t" :value="t">{{ t }}</option>
            </select>
          </div>
          <div class="form-group" style="margin:0;flex:1;min-width:180px">
            <label>Since</label>
            <input type="datetime-local" v-model="filterSince" @change="load" />
          </div>
          <button class="btn btn-ghost btn-sm" @click="clearFilters">Clear</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>{{ events.length }} event{{ events.length !== 1 ? 's' : '' }}</h2>
        <span v-if="filterType || filterSince" class="badge badge-blue">filtered</span>
      </div>
      <div class="table-wrap">
        <table v-if="events.length">
          <thead>
            <tr>
              <th>Time</th>
              <th>Event Type</th>
              <th>Actor</th>
              <th>Resource</th>
              <th>Metadata</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="e in events" :key="e.id">
              <td style="white-space:nowrap;font-size:12px">{{ formatDate(e.timestamp) }}</td>
              <td><code style="font-size:12px">{{ e.event_type }}</code></td>
              <td>{{ e.actor }}</td>
              <td><code style="font-size:12px">{{ e.resource_id || '—' }}</code></td>
              <td>
                <span v-if="e.metadata && Object.keys(e.metadata).length" style="font-size:12px;font-family:monospace">
                  {{ JSON.stringify(e.metadata) }}
                </span>
                <span v-else style="color:var(--text-muted)">—</span>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">
          <svg v-if="loading" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-bottom:12px;opacity:.4;animation:spin .8s linear infinite"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/><style>@keyframes spin{to{transform:rotate(360deg)}}</style></svg>
          <svg v-else width="32" height="32" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.2" style="margin-bottom:12px;opacity:.4"><path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h7a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h4a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd"/></svg>
          <div style="margin-bottom:4px;font-weight:500;color:var(--text)">{{ loading ? 'Loading…' : 'No audit events' }}</div>
          <div v-if="!loading">{{ filterType || filterSince ? 'No events match the current filter.' : 'Events are recorded as users and groups are created, updated, and deleted.' }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref, onMounted } from 'vue'

interface AuditEvent {
  id: string
  timestamp: string
  event_type: string
  actor: string
  resource_id: string
  metadata?: Record<string, any>
}

const events = ref<AuditEvent[]>([])
const loading = ref(false)
const filterType = ref('')
const filterSince = ref('')

const knownTypes = [
  'user.created', 'user.updated', 'user.deleted',
  'flow.complete', 'flow.denied', 'flow.mfa_approved',
]

async function load() {
  loading.value = true
  try {
    const params = new URLSearchParams()
    if (filterType.value) params.set('event_type', filterType.value)
    if (filterSince.value) params.set('since', new Date(filterSince.value).toISOString())
    const qs = params.toString() ? '?' + params.toString() : ''
    const res = await apiFetch('/api/v1/audit' + qs)
    if (!res.ok) throw new Error('fetch failed')
    events.value = await res.json()
  } catch {
    events.value = []
  } finally {
    loading.value = false
  }
}

function clearFilters() {
  filterType.value = ''
  filterSince.value = ''
  load()
}

function formatDate(iso: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

onMounted(load)
</script>
