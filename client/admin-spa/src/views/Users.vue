<template>
  <div class="page">
    <div class="page-header">
      <h1>Users</h1>
      <button class="btn btn-primary" @click="openCreate">+ New User</button>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>{{ users.length }} user{{ users.length !== 1 ? 's' : '' }}</h2>
        <input
          v-model="search"
          placeholder="Search by email or name…"
          style="padding:5px 9px;border:1px solid var(--border);border-radius:var(--radius);font-size:13px;width:220px"
        />
      </div>
      <div class="table-wrap">
        <table v-if="filtered.length">
          <thead>
            <tr>
              <th>Email</th>
              <th>Display Name</th>
              <th>MFA Method</th>
              <th>Groups</th>
              <th>Next Flow</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in filtered" :key="u.id">
              <td>{{ u.email }}</td>
              <td>{{ u.display_name }}</td>
              <td>
                <span class="badge" :class="mfaBadge(u.mfa_method)">{{ u.mfa_method || 'none' }}</span>
              </td>
              <td>
                <span v-for="g in u.groups" :key="g" class="badge badge-gray" style="margin-right:3px">{{ g }}</span>
                <span v-if="!u.groups?.length" class="badge badge-gray">—</span>
              </td>
              <td>
                <span v-if="u.next_flow && u.next_flow !== 'normal'" class="badge badge-yellow">{{ u.next_flow }}</span>
                <span v-else class="badge badge-gray">normal</span>
              </td>
              <td style="white-space:nowrap">
                <button class="btn btn-ghost btn-sm" @click="openEdit(u)">Edit</button>
                <button class="btn btn-danger btn-sm" style="margin-left:4px" @click="deleteUser(u)">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">No users found.</div>
      </div>
    </div>

    <!-- Create / Edit modal -->
    <div v-if="modal" class="modal-backdrop" @click.self="modal = null">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ modal.id ? 'Edit User' : 'New User' }}</h3>
          <button class="modal-close" @click="modal = null">&times;</button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label>Email</label>
            <input v-model="modal.email" type="email" placeholder="alice@example.com" />
          </div>
          <div class="form-group">
            <label>Display Name</label>
            <input v-model="modal.display_name" placeholder="Alice Smith" />
          </div>
          <div class="form-group">
            <label>MFA Method</label>
            <select v-model="modal.mfa_method">
              <option value="">None</option>
              <option value="totp">TOTP</option>
              <option value="push">Push</option>
              <option value="sms">SMS</option>
              <option value="magic_link">Magic Link</option>
            </select>
          </div>
          <div class="form-group">
            <label>Next Flow Scenario</label>
            <select v-model="modal.next_flow">
              <option value="normal">normal</option>
              <option value="mfa_fail">mfa_fail</option>
              <option value="account_locked">account_locked</option>
              <option value="slow_mfa">slow_mfa</option>
              <option value="expired_token">expired_token</option>
            </select>
          </div>
          <div class="form-group">
            <label>Phone Number</label>
            <input v-model="modal.phone_number" placeholder="+1555000000 (optional)" />
          </div>
          <div v-if="modalError" class="error-msg">{{ modalError }}</div>
          <div class="form-actions">
            <button class="btn btn-ghost" @click="modal = null">Cancel</button>
            <button class="btn btn-primary" @click="saveUser">Save</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref, computed, onMounted } from 'vue'

interface User {
  id: string
  email: string
  display_name: string
  mfa_method: string
  groups: string[]
  next_flow: string
  phone_number: string
}

const users = ref<User[]>([])
const search = ref('')
const modal = ref<Partial<User> | null>(null)
const modalError = ref('')

const filtered = computed(() => {
  const q = search.value.toLowerCase()
  if (!q) return users.value
  return users.value.filter(u =>
    u.email.toLowerCase().includes(q) || u.display_name.toLowerCase().includes(q)
  )
})

async function load() {
  const res = await apiFetch('/api/v1/users')
  users.value = await res.json()
}

function openCreate() {
  modal.value = { email: '', display_name: '', mfa_method: '', next_flow: 'normal', phone_number: '', groups: [] }
  modalError.value = ''
}

function openEdit(u: User) {
  modal.value = { ...u }
  modalError.value = ''
}

async function saveUser() {
  modalError.value = ''
  const u = modal.value!
  const isNew = !u.id

  if (!u.email) { modalError.value = 'Email is required.'; return }

  let res: Response
  if (isNew) {
    const id = 'usr_' + Date.now()
    res = await apiFetch('/api/v1/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...u, id }),
    })
  } else {
    res = await apiFetch(`/api/v1/users/${u.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(u),
    })
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    modalError.value = body?.error?.message ?? `Request failed (${res.status})`
    return
  }
  modal.value = null
  await load()
}

async function deleteUser(u: User) {
  if (!confirm(`Delete ${u.email}?`)) return
  await apiFetch(`/api/v1/users/${u.id}`, { method: 'DELETE' })
  await load()
}

function mfaBadge(method: string) {
  switch (method) {
    case 'totp':       return 'badge-blue'
    case 'push':       return 'badge-green'
    case 'sms':        return 'badge-yellow'
    case 'magic_link': return 'badge-blue'
    default:           return 'badge-gray'
  }
}

onMounted(load)
</script>
