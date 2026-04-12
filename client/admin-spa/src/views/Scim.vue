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
  </div>
</template>

<script setup lang="ts">
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

const scimUsers = ref<SCIMUser[]>([])
const scimGroups = ref<SCIMGroup[]>([])
const spcJSON = ref('')
const filter = ref('')
const usersLoading = ref(false)
const groupsLoading = ref(false)
const error = ref('')

async function loadUsers() {
  usersLoading.value = true
  error.value = ''
  try {
    const url = filter.value.trim()
      ? `/scim/v2/Users?filter=${encodeURIComponent(`userName eq "${filter.value.trim()}"`)}`
      : '/scim/v2/Users'
    const res = await fetch(url, { headers: { Accept: 'application/scim+json' } })
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
    const res = await fetch('/scim/v2/Groups', { headers: { Accept: 'application/scim+json' } })
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
    const res = await fetch('/scim/v2/ServiceProviderConfig', { headers: { Accept: 'application/scim+json' } })
    if (!res.ok) return
    spcJSON.value = JSON.stringify(await res.json(), null, 2)
  } catch { /* ignore */ }
}

onMounted(() => {
  loadUsers()
  loadGroups()
  loadSPC()
})
</script>
