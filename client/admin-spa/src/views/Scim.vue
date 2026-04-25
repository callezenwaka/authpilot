<template>
  <div class="page">
    <div class="page-header">
      <h1>SCIM Provisioning</h1>
    </div>

    <div class="stat-grid" style="grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-bottom:24px">
      <div class="stat-card">
        <div class="label">SCIM Users</div>
        <div class="value">{{ scimUsers.length }}</div>
      </div>
      <div class="stat-card">
        <div class="label">SCIM Groups</div>
        <div class="value">{{ scimGroups.length }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Filter / userName eq</div>
        <div class="value" style="font-size:13px;font-weight:500;margin-top:8px">
          <input
            v-model="filter"
            placeholder="alice@example.com"
            style="width:100%;padding:5px 9px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px"
            @keyup.enter="loadUsers"
          />
          <button class="btn btn-ghost btn-sm" style="margin-top:6px;width:100%" @click="loadUsers">Search</button>
        </div>
      </div>
    </div>

    <!-- Users table -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <h2>Users</h2>
        <span class="badge badge-gray">via /scim/v2/Users</span>
      </div>
      <div class="table-wrap">
        <table v-if="scimUsers.length">
          <thead>
            <tr>
              <th>ID</th>
              <th>userName</th>
              <th>displayName</th>
              <th>Active</th>
              <th>Groups</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in scimUsers" :key="u.id">
              <td><code>{{ u.id }}</code></td>
              <td>{{ u.userName }}</td>
              <td>{{ u.displayName || '—' }}</td>
              <td>
                <span class="badge" :class="u.active ? 'badge-green' : 'badge-gray'">
                  {{ u.active ? 'active' : 'inactive' }}
                </span>
              </td>
              <td>
                <span v-for="g in (u.groups ?? [])" :key="g.value" class="badge badge-gray" style="margin-right:3px">
                  {{ g.display || g.value }}
                </span>
                <span v-if="!(u.groups?.length)" class="badge badge-gray">—</span>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">{{ usersLoading ? 'Loading…' : 'No users found.' }}</div>
      </div>
    </div>

    <!-- Groups table -->
    <div class="card">
      <div class="card-header">
        <h2>Groups</h2>
        <span class="badge badge-gray">via /scim/v2/Groups</span>
      </div>
      <div class="table-wrap">
        <table v-if="scimGroups.length">
          <thead>
            <tr>
              <th>ID</th>
              <th>displayName</th>
              <th>Members</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="g in scimGroups" :key="g.id">
              <td><code>{{ g.id }}</code></td>
              <td>{{ g.displayName }}</td>
              <td>
                <span v-for="m in (g.members ?? [])" :key="m.value" class="badge badge-gray" style="margin-right:3px">
                  {{ m.display || m.value }}
                </span>
                <span v-if="!(g.members?.length)" class="badge badge-gray">—</span>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">{{ groupsLoading ? 'Loading…' : 'No groups found.' }}</div>
      </div>
    </div>

    <!-- Service Provider Config -->
    <details style="margin-top:20px">
      <summary style="cursor:pointer;font-size:13px;font-weight:600;color:var(--text-muted);padding:4px 0">
        ServiceProviderConfig
      </summary>
      <div class="card" style="margin-top:10px">
        <div class="card-body">
          <pre style="font-size:12px;margin:0;overflow-x:auto">{{ spcJSON }}</pre>
        </div>
      </div>
    </details>

    <div v-if="error" class="error-msg" style="margin-top:12px">{{ error }}</div>

    <!-- SCIM Client Events (BUI9) -->
    <div style="margin-top:28px">
      <div class="page-header" style="margin-bottom:14px">
        <h2 style="margin:0;font-size:16px;font-weight:700">Outbound SCIM Events</h2>
        <button class="btn btn-ghost btn-sm" @click="loadEvents">Refresh</button>
      </div>
      <div class="card">
        <div class="card-header">
          <h2>{{ scimEvents.length }} event{{ scimEvents.length !== 1 ? 's' : '' }}</h2>
          <span class="badge badge-gray">FURNACE_SCIM_MODE=client</span>
        </div>
        <div class="table-wrap">
          <table v-if="scimEvents.length">
            <thead>
              <tr>
                <th>Time</th>
                <th>Method</th>
                <th>URL</th>
                <th>Status</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              <template v-for="ev in scimEvents" :key="ev.id ?? ev.timestamp">
                <tr @click="toggleEvent(ev.timestamp)" style="cursor:pointer">
                  <td style="white-space:nowrap;font-size:12px">{{ formatDate(ev.timestamp) }}</td>
                  <td><span class="badge" :class="methodBadge(ev.method)">{{ ev.method }}</span></td>
                  <td style="font-size:12px;font-family:monospace;word-break:break-all">{{ ev.url }}</td>
                  <td>
                    <span v-if="ev.response_status" class="badge" :class="statusBadge(ev.response_status)">
                      {{ ev.response_status }}
                    </span>
                    <span v-else class="badge badge-gray">—</span>
                  </td>
                  <td style="font-size:12px;color:var(--danger)">{{ ev.error || '' }}</td>
                </tr>
                <tr v-if="expandedEvent === ev.timestamp">
                  <td colspan="5" style="background:#f8faff;padding:14px 18px">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
                      <div>
                        <div style="font-size:11px;font-weight:700;color:var(--text-muted);margin-bottom:4px">REQUEST BODY</div>
                        <pre style="font-size:11px;margin:0;overflow-x:auto;white-space:pre-wrap">{{ prettyJSON(ev.request_body) }}</pre>
                      </div>
                      <div>
                        <div style="font-size:11px;font-weight:700;color:var(--text-muted);margin-bottom:4px">RESPONSE BODY</div>
                        <pre style="font-size:11px;margin:0;overflow-x:auto;white-space:pre-wrap">{{ prettyJSON(ev.response_body) }}</pre>
                      </div>
                    </div>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
          <div v-else-if="eventsDisabled" class="empty">
            SCIM client mode is not enabled.<br>
            Set <code>FURNACE_SCIM_MODE=client</code> and <code>FURNACE_SCIM_TARGET=&lt;url&gt;</code> to activate.
          </div>
          <div v-else class="empty">{{ eventsLoading ? 'Loading…' : 'No outbound SCIM events yet.' }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref, onMounted } from 'vue'

interface SCIMUser {
  id: string
  userName: string
  displayName: string
  active: boolean
  groups?: { value: string; display?: string }[]
}

interface SCIMGroup {
  id: string
  displayName: string
  members?: { value: string; display?: string }[]
}

interface SCIMEvent {
  id?: string
  timestamp: string
  method: string
  url: string
  request_body?: string
  response_status?: number
  response_body?: string
  error?: string
}

const scimUsers = ref<SCIMUser[]>([])
const scimGroups = ref<SCIMGroup[]>([])
const spcJSON = ref('')
const filter = ref('')
const usersLoading = ref(false)
const groupsLoading = ref(false)
const error = ref('')
const scimEvents = ref<SCIMEvent[]>([])
const eventsLoading = ref(false)
const eventsDisabled = ref(false)
const expandedEvent = ref<string | null>(null)

async function loadUsers() {
  usersLoading.value = true
  error.value = ''
  try {
    const url = filter.value.trim()
      ? `/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${filter.value.trim()}"`)}`
      : '/scim/v2/Users'
    const res = await apiFetch(url, { headers: { Accept: 'application/scim+json' } })
    if (!res.ok) throw new Error(`SCIM ${res.status}`)
    const data = await res.json()
    scimUsers.value = Array.isArray(data.Resources) ? data.Resources : []
  } catch (e: any) {
    error.value = e.message
  } finally {
    usersLoading.value = false
  }
}

async function loadGroups() {
  groupsLoading.value = true
  try {
    const res = await apiFetch('/scim/v2/Groups', { headers: { Accept: 'application/scim+json' } })
    if (!res.ok) throw new Error(`SCIM ${res.status}`)
    const data = await res.json()
    scimGroups.value = Array.isArray(data.Resources) ? data.Resources : []
  } catch (e: any) {
    error.value = e.message
  } finally {
    groupsLoading.value = false
  }
}

async function loadSPC() {
  try {
    const res = await apiFetch('/scim/v2/ServiceProviderConfig', { headers: { Accept: 'application/scim+json' } })
    if (!res.ok) return
    spcJSON.value = JSON.stringify(await res.json(), null, 2)
  } catch { /* ignore */ }
}

async function loadEvents() {
  eventsLoading.value = true
  eventsDisabled.value = false
  try {
    const res = await apiFetch('/api/v1/scim/events')
    if (res.status === 501) { eventsDisabled.value = true; scimEvents.value = []; return }
    if (!res.ok) throw new Error(`${res.status}`)
    scimEvents.value = await res.json()
  } catch {
    scimEvents.value = []
  } finally {
    eventsLoading.value = false
  }
}

function toggleEvent(ts: string) {
  expandedEvent.value = expandedEvent.value === ts ? null : ts
}

function formatDate(iso: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

function methodBadge(method: string) {
  switch (method) {
    case 'POST':   return 'badge-blue'
    case 'PUT':    return 'badge-yellow'
    case 'DELETE': return 'badge-red'
    default:       return 'badge-gray'
  }
}

function statusBadge(status: number) {
  if (status >= 200 && status < 300) return 'badge-green'
  if (status >= 400) return 'badge-red'
  return 'badge-gray'
}

function prettyJSON(raw: string | undefined) {
  if (!raw) return '—'
  try { return JSON.stringify(JSON.parse(raw), null, 2) }
  catch { return raw }
}

onMounted(() => {
  loadUsers()
  loadGroups()
  loadSPC()
  loadEvents()
})
</script>
