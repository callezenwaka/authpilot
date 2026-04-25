<template>
  <div class="page">
    <div class="page-header">
      <h1>Groups</h1>
      <button class="btn btn-primary" @click="openCreate">+ New Group</button>
    </div>

    <div class="card">
      <div class="card-header">
        <h2>{{ groups.length }} group{{ groups.length !== 1 ? 's' : '' }}</h2>
      </div>
      <div class="table-wrap">
        <table v-if="groups.length">
          <thead>
            <tr>
              <th>ID</th>
              <th>Display Name</th>
              <th>Members</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="g in groups" :key="g.id">
              <td><code>{{ g.id }}</code></td>
              <td>{{ g.display_name || g.name }}</td>
              <td>{{ g.member_ids?.length ?? 0 }}</td>
              <td style="white-space:nowrap">
                <button class="btn btn-ghost btn-sm" @click="openEdit(g)">Edit</button>
                <button class="btn btn-danger btn-sm" style="margin-left:4px" @click="deleteGroup(g)">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">
          <svg width="32" height="32" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.2" style="margin-bottom:12px;opacity:.4"><path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v1h8v-1zM6 8a2 2 0 11-4 0 2 2 0 014 0zM16 18v-1a5.97 5.97 0 00-.75-2.906A3.005 3.005 0 0119 15v1h-3zM4.75 14.094A5.97 5.97 0 004 17v1H1v-1a3 3 0 013.75-2.906z"/></svg>
          <div style="margin-bottom:8px;font-weight:500;color:var(--text)">No groups yet</div>
          <div style="margin-bottom:16px">Create a group to organise users by team or role.</div>
          <button class="btn btn-primary btn-sm" @click="openCreate">+ New Group</button>
        </div>
      </div>
    </div>

    <!-- Create / Edit modal -->
    <div v-if="modal" class="modal-backdrop" @click.self="modal = null">
      <div class="modal">
        <div class="modal-header">
          <h3>{{ modal.id ? 'Edit Group' : 'New Group' }}</h3>
          <button class="modal-close" @click="modal = null">&times;</button>
        </div>
        <div class="modal-body">
          <div class="form-group">
            <label>ID</label>
            <input v-model="modal.id" :disabled="!!editingId" placeholder="engineering" />
          </div>
          <div class="form-group">
            <label>Name</label>
            <input v-model="modal.name" placeholder="engineering" />
          </div>
          <div class="form-group">
            <label>Display Name</label>
            <input v-model="modal.display_name" placeholder="Engineering Team" />
          </div>
          <div class="form-group">
            <label>Member User IDs (one per line)</label>
            <textarea v-model="memberText" rows="4" placeholder="usr_001&#10;usr_002" />
          </div>
          <div v-if="modalError" class="error-msg">{{ modalError }}</div>
          <div class="form-actions">
            <button class="btn btn-ghost" @click="modal = null">Cancel</button>
            <button class="btn btn-primary" @click="saveGroup">Save</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref, onMounted } from 'vue'

interface Group {
  id: string
  name: string
  display_name: string
  member_ids: string[]
}

const groups = ref<Group[]>([])
const modal = ref<Partial<Group> | null>(null)
const editingId = ref('')
const memberText = ref('')
const modalError = ref('')

async function load() {
  const res = await apiFetch('/api/v1/groups')
  groups.value = await res.json()
}

function openCreate() {
  modal.value = { id: '', name: '', display_name: '', member_ids: [] }
  editingId.value = ''
  memberText.value = ''
  modalError.value = ''
}

function openEdit(g: Group) {
  modal.value = { ...g }
  editingId.value = g.id
  memberText.value = (g.member_ids ?? []).join('\n')
  modalError.value = ''
}

async function saveGroup() {
  modalError.value = ''
  const g = modal.value!
  if (!g.id) { modalError.value = 'ID is required.'; return }

  g.member_ids = memberText.value.split('\n').map(s => s.trim()).filter(Boolean)

  const isNew = !editingId.value
  const res = await apiFetch(isNew ? '/api/v1/groups' : `/api/v1/groups/${editingId.value}`, {
    method: isNew ? 'POST' : 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(g),
  })

  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    modalError.value = body?.error?.message ?? `Request failed (${res.status})`
    return
  }
  modal.value = null
  await load()
}

async function deleteGroup(g: Group) {
  if (!confirm(`Delete group "${g.display_name || g.id}"?`)) return
  await apiFetch(`/api/v1/groups/${g.id}`, { method: 'DELETE' })
  await load()
}

onMounted(load)
</script>
