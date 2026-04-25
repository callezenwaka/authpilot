<template>
  <div class="page">
    <div class="page-header">
      <h1>Dashboard</h1>
    </div>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="label">Users</div>
        <div class="value">{{ stats.users }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Groups</div>
        <div class="value">{{ stats.groups }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Active Flows</div>
        <div class="value">{{ stats.activeFlows }}</div>
      </div>
      <div class="stat-card">
        <div class="label">Sessions</div>
        <div class="value">{{ stats.sessions }}</div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>Recent Sessions</h2>
        <router-link to="/sessions" class="btn btn-ghost btn-sm">View all</router-link>
      </div>
      <div class="table-wrap">
        <table v-if="recentSessions.length">
          <thead>
            <tr>
              <th>Session ID</th>
              <th>User</th>
              <th>Flow</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in recentSessions" :key="s.id">
              <td><code>{{ s.id }}</code></td>
              <td>{{ s.user_id }}</td>
              <td><code>{{ s.flow_id }}</code></td>
              <td>{{ formatDate(s.created_at) }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">No sessions yet.</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref, onMounted } from 'vue'

interface Session {
  id: string
  user_id: string
  flow_id: string
  created_at: string
}

const stats = ref({ users: 0, groups: 0, activeFlows: 0, sessions: 0 })
const recentSessions = ref<Session[]>([])

async function load() {
  const [users, groups, flows, sessions] = await Promise.all([
    apiFetch('/api/v1/users').then(r => r.json()),
    apiFetch('/api/v1/groups').then(r => r.json()),
    apiFetch('/api/v1/flows').then(r => r.json()),
    apiFetch('/api/v1/sessions').then(r => r.json()),
  ])
  stats.value.users = Array.isArray(users) ? users.length : 0
  stats.value.groups = Array.isArray(groups) ? groups.length : 0
  stats.value.activeFlows = Array.isArray(flows)
    ? flows.filter((f: any) => f.state !== 'complete' && f.state !== 'error').length
    : 0
  stats.value.sessions = Array.isArray(sessions) ? sessions.length : 0
  recentSessions.value = Array.isArray(sessions) ? sessions.slice(-10).reverse() : []
}

function formatDate(iso: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

onMounted(load)
</script>
