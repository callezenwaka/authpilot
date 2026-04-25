<template>
  <dialog ref="dialogEl" class="notify-dialog" @cancel.prevent="close">
    <div class="nd-header">
      <div class="nd-title">
        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a6 6 0 00-6 6v3.586l-.707.707A1 1 0 004 14h12a1 1 0 00.707-1.707L16 11.586V8a6 6 0 00-6-6zM10 18a3 3 0 01-3-3h6a3 3 0 01-3 3z"/></svg>
        Notification Hub
      </div>
      <button class="nd-close" @click="close" aria-label="Close">&times;</button>
    </div>

    <nav class="nd-tabs" role="tablist">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        role="tab"
        :aria-selected="activeTab === tab.id"
        :class="['nd-tab', { active: activeTab === tab.id }]"
        @click="activeTab = tab.id"
      >
        {{ tab.label }}
        <span v-if="countFor(tab.id) > 0" class="nd-count">{{ countFor(tab.id) }}</span>
      </button>
    </nav>

    <div class="nd-body" role="tabpanel">

      <!-- TOTP -->
      <template v-if="activeTab === 'totp'">
        <div v-if="totpItems.length === 0" class="nd-empty">No pending TOTP flows.</div>
        <div v-for="item in totpItems" :key="item.flow_id" class="nd-card">
          <div class="nd-card-header">
            <span>{{ item.user_email || item.user_id }}</span>
            <span class="badge badge-blue">TOTP</span>
          </div>
          <div class="nd-code">{{ item.totp_code }}</div>
          <div class="nd-timer">
            <span>⏱ {{ secondsLeft(item.totp_expires_at) }}s remaining</span>
            <div class="nd-timer-bar">
              <div class="nd-timer-fill" :style="{ width: timerPercent(item.totp_expires_at) + '%' }"></div>
            </div>
          </div>
          <div class="nd-actions">
            <button class="btn btn-ghost btn-sm" @click="copy(item.totp_code)">Copy Code</button>
          </div>
        </div>
      </template>

      <!-- Push -->
      <template v-if="activeTab === 'push'">
        <div v-if="pushItems.length === 0" class="nd-empty">No pending push approvals.</div>
        <div v-for="item in pushItems" :key="item.flow_id" class="nd-card">
          <div class="nd-card-header">
            <span style="font-weight:600">Sign-in Request</span>
          </div>
          <div class="nd-meta">{{ item.user_email || item.user_id }}</div>
          <div class="nd-meta">Flow: <code style="font-size:11px">{{ item.flow_id }}</code></div>
          <div class="nd-actions">
            <button class="btn btn-primary btn-sm" @click="approve(item)">✓ Approve</button>
            <button class="btn btn-danger btn-sm" @click="deny(item)">✗ Deny</button>
          </div>
        </div>
      </template>

      <!-- SMS -->
      <template v-if="activeTab === 'sms'">
        <div v-if="smsItems.length === 0" class="nd-empty">No pending SMS codes.</div>
        <div v-for="item in smsItems" :key="item.flow_id" class="nd-card">
          <div class="nd-meta">{{ item.sms_target || 'Unknown number' }}</div>
          <div style="margin:8px 0">Code: <strong style="font-size:1.1rem;letter-spacing:.1em">{{ item.sms_code }}</strong></div>
          <div class="nd-meta">Flow: {{ item.flow_id }}</div>
          <div class="nd-actions">
            <button class="btn btn-ghost btn-sm" @click="copy(item.sms_code)">Copy Code</button>
          </div>
        </div>
      </template>

      <!-- Magic Links -->
      <template v-if="activeTab === 'magic'">
        <div v-if="magicItems.length === 0" class="nd-empty">No pending magic links.</div>
        <div v-for="item in magicItems" :key="item.flow_id" class="nd-card">
          <div class="nd-meta">To: {{ item.user_email || item.user_id }}</div>
          <div style="margin:8px 0;font-weight:500">Sign in to My Dev App</div>
          <span v-if="item.magic_link_used" style="color:var(--text-muted);font-size:.85rem">Link already used.</span>
          <a v-else :href="item.magic_link_url" class="btn btn-primary btn-sm" style="text-decoration:none">Sign In</a>
        </div>
      </template>

      <!-- Passkeys (WebAuthn) -->
      <template v-if="activeTab === 'webauthn'">
        <div v-if="webauthnItems.length === 0" class="nd-empty">No pending passkey authentications.</div>
        <div v-for="item in webauthnItems" :key="item.flow_id" class="nd-card">
          <div class="nd-card-header">
            <span style="font-weight:600">Passkey Authentication</span>
            <span class="badge badge-blue">WebAuthn</span>
          </div>
          <div class="nd-meta">{{ item.user_email || item.user_id }}</div>
          <div class="nd-meta" style="word-break:break-all">
            Challenge: <code style="font-size:11px">{{ item.webauthn_challenge }}</code>
          </div>
          <div class="nd-meta" style="margin-top:10px;color:var(--text)">
            Complete authentication on the <a href="/login" target="_blank" style="color:var(--primary)">login page</a> — your browser will prompt for Touch ID or your security key.
          </div>
        </div>
      </template>

    </div>
  </dialog>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref, computed, onMounted, onUnmounted } from 'vue'

interface NotifyPayload {
  flow_id: string
  type: string
  user_id: string
  user_email: string
  totp_code?: string
  totp_expires_at?: string
  sms_code?: string
  sms_target?: string
  push_pending?: boolean
  magic_link_url?: string
  magic_link_used?: boolean
  webauthn_challenge?: string
  webauthn_credential_id?: string
}

const tabs = [
  { id: 'totp',    label: 'TOTP' },
  { id: 'push',    label: 'Push' },
  { id: 'sms',     label: 'SMS' },
  { id: 'magic',   label: 'Magic Links' },
  { id: 'webauthn', label: 'Passkeys' },
]

const dialogEl  = ref<HTMLDialogElement | null>(null)
const activeTab = ref('totp')
const items     = ref<NotifyPayload[]>([])
const now       = ref(Date.now())
const isOpen    = ref(false)

let pollTimer:  ReturnType<typeof setInterval> | null = null
let clockTimer: ReturnType<typeof setInterval> | null = null

const totpItems    = computed(() => items.value.filter(i => i.type === 'totp'))
const pushItems    = computed(() => items.value.filter(i => i.type === 'push'))
const smsItems     = computed(() => items.value.filter(i => i.type === 'sms'))
const magicItems   = computed(() => items.value.filter(i => i.type === 'magic_link'))
const webauthnItems = computed(() => items.value.filter(i => i.type === 'webauthn'))


function countFor(tabId: string): number {
  switch (tabId) {
    case 'totp':    return totpItems.value.length
    case 'push':    return pushItems.value.length
    case 'sms':     return smsItems.value.length
    case 'magic':   return magicItems.value.length
    case 'webauthn': return webauthnItems.value.length
    default:        return 0
  }
}

async function load() {
  try {
    const res = await apiFetch('/api/v1/notifications/all')
    if (res.ok) items.value = await res.json()
  } catch { /* server unreachable during dev */ }
}

function startPolling() {
  load()
  pollTimer  = setInterval(load, 3000)
  clockTimer = setInterval(() => { now.value = Date.now() }, 1000)
}

function stopPolling() {
  if (pollTimer)  { clearInterval(pollTimer);  pollTimer  = null }
  if (clockTimer) { clearInterval(clockTimer); clockTimer = null }
}

function open() {
  dialogEl.value?.showModal()
  isOpen.value = true
  startPolling()
}

function close() {
  dialogEl.value?.close()
  isOpen.value = false
  stopPolling()
}

function secondsLeft(expiresAt?: string): number {
  if (!expiresAt) return 0
  return Math.max(0, Math.floor((new Date(expiresAt).getTime() - now.value) / 1000))
}

function timerPercent(expiresAt?: string): number {
  if (!expiresAt) return 0
  const left = new Date(expiresAt).getTime() - now.value
  return Math.max(0, Math.min(100, (left / 30000) * 100))
}

function copy(text?: string) {
  if (text) navigator.clipboard.writeText(text)
}

async function approve(item: NotifyPayload) {
  await apiFetch(`/api/v1/flows/${item.flow_id}/approve`, { method: 'POST' })
  await load()
}

async function deny(item: NotifyPayload) {
  await apiFetch(`/api/v1/flows/${item.flow_id}/deny`, { method: 'POST' })
  await load()
}


onMounted(() => {
  // Initial lightweight fetch so the badge count is available immediately
  load()
})

onUnmounted(stopPolling)

defineExpose({ open })
</script>

<style scoped>
.notify-dialog {
  border: none;
  border-radius: 8px;
  padding: 0;
  width: 480px;
  max-width: 95vw;
  max-height: 80vh;
  overflow: hidden;
  box-shadow: 0 8px 32px rgba(0,0,0,.2);
}

.notify-dialog[open] {
  display: flex;
  flex-direction: column;
}

.notify-dialog::backdrop {
  background: rgba(0,0,0,.45);
}

.nd-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  flex-shrink: 0;
}

.nd-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
  font-size: 14px;
  color: var(--text);
}

.nd-close {
  background: none;
  border: none;
  font-size: 20px;
  cursor: pointer;
  color: var(--text-muted);
  line-height: 1;
  padding: 0 4px;
}
.nd-close:hover { color: var(--text); }

.nd-tabs {
  display: flex;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0 12px;
  gap: 2px;
  flex-shrink: 0;
}

.nd-tab {
  display: flex;
  align-items: center;
  gap: 5px;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  padding: 10px 10px 9px;
  font-size: 13px;
  color: var(--text-muted);
  cursor: pointer;
  transition: color .15s, border-color .15s;
}
.nd-tab:hover { color: var(--text); }
.nd-tab.active { color: var(--primary); border-bottom-color: var(--primary); }

.nd-count {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 700;
  background: var(--primary);
  color: #fff;
}

.nd-body {
  overflow-y: auto;
  padding: 16px;
  background: var(--bg);
  flex: 1;
}

.nd-empty {
  text-align: center;
  padding: 40px 16px;
  color: var(--text-muted);
  font-size: 13px;
}

.nd-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 16px;
  margin-bottom: 10px;
  box-shadow: var(--shadow);
}

.nd-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
  font-size: 13px;
}

.nd-badge-blue { background: #dbeafe; color: #1d4ed8; border-radius: 999px; padding: 1px 7px; font-size: 11px; font-weight: 600; }

.nd-code {
  font-size: 2rem;
  font-weight: 700;
  letter-spacing: .15em;
  font-family: monospace;
  color: var(--primary);
  margin-bottom: 10px;
}

.nd-timer { font-size: 12px; color: var(--text-muted); margin-bottom: 10px; }
.nd-timer-bar { height: 4px; background: var(--border); border-radius: 2px; margin-top: 4px; overflow: hidden; }
.nd-timer-fill { height: 100%; background: var(--primary); border-radius: 2px; transition: width 1s linear; }

.nd-meta { font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }

.nd-actions { display: flex; gap: 8px; margin-top: 12px; }
</style>
