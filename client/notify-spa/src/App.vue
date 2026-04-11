<template>
  <div>
    <header class="topbar">
      <span class="topbar-title">Auth<span>pilot</span> — Notification Hub</span>
      <a href="/admin" class="topbar-link">Admin →</a>
    </header>

    <nav class="tabs">
      <span
        v-for="tab in tabs"
        :key="tab.id"
        class="tab"
        :class="{ active: activeTab === tab.id }"
        @click="activeTab = tab.id"
      >{{ tab.label }}</span>
    </nav>

    <div class="page">

      <!-- TOTP -->
      <template v-if="activeTab === 'totp'">
        <div v-if="totpItems.length === 0" class="empty">No pending TOTP flows.</div>
        <div v-for="item in totpItems" :key="item.flow_id" class="card">
          <div class="card-header">
            <h3>{{ item.user_email || item.user_id }}</h3>
            <span class="badge badge-blue">TOTP</span>
          </div>
          <div class="card-body">
            <div class="code-display">{{ item.totp_code }}</div>
            <div class="timer">
              ⏱ {{ secondsLeft(item.totp_expires_at) }}s remaining
              <div class="timer-bar">
                <div class="timer-fill" :style="{ width: timerPercent(item.totp_expires_at) + '%' }"></div>
              </div>
            </div>
            <div class="row">
              <button class="btn btn-ghost" @click="copy(item.totp_code)">Copy Code</button>
              <button class="btn btn-primary" @click="useCode(item)">Use This Code</button>
            </div>
          </div>
        </div>
      </template>

      <!-- Push -->
      <template v-if="activeTab === 'push'">
        <div v-if="pushItems.length === 0" class="empty">No pending push approvals.</div>
        <div v-for="item in pushItems" :key="item.flow_id" class="card">
          <div class="push-card">
            <div style="font-weight:600">Sign-in Request</div>
            <div class="push-meta">{{ item.user_email || item.user_id }}</div>
            <div class="push-meta" style="margin-top:2px">Flow: <code style="font-size:11px">{{ item.flow_id }}</code></div>
            <div class="push-actions">
              <button class="btn btn-success" @click="approve(item)">✓ Approve</button>
              <button class="btn btn-danger" @click="deny(item)">✗ Deny</button>
            </div>
          </div>
        </div>
      </template>

      <!-- SMS -->
      <template v-if="activeTab === 'sms'">
        <div v-if="smsItems.length === 0" class="empty">No pending SMS codes.</div>
        <div v-if="smsItems.length" class="card">
          <div v-for="item in smsItems" :key="item.flow_id" class="sms-entry">
            <div class="sms-phone">{{ item.sms_target || 'Unknown number' }}</div>
            <div class="sms-body">Your verification code is: <strong>{{ item.sms_code }}</strong></div>
            <div class="sms-meta">Flow: {{ item.flow_id }}</div>
            <button class="btn btn-ghost" @click="copy(item.sms_code)">Copy Code</button>
          </div>
        </div>
      </template>

      <!-- Magic Links -->
      <template v-if="activeTab === 'magic'">
        <div v-if="magicItems.length === 0" class="empty">No pending magic links.</div>
        <div v-if="magicItems.length" class="card">
          <div v-for="item in magicItems" :key="item.flow_id" class="magic-entry">
            <div class="magic-to">To: {{ item.user_email || item.user_id }}</div>
            <div class="magic-subject">Sign in to My Dev App</div>
            <template v-if="item.magic_link_used">
              <span class="magic-used">Link already used.</span>
            </template>
            <template v-else>
              <a :href="item.magic_link_url" class="btn btn-primary" style="display:inline-flex;text-decoration:none">
                Sign In
              </a>
            </template>
          </div>
        </div>
      </template>

    </div>
  </div>
</template>

<script setup lang="ts">
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
}

const tabs = [
  { id: 'totp',  label: 'TOTP' },
  { id: 'push',  label: 'Push' },
  { id: 'sms',   label: 'SMS' },
  { id: 'magic', label: 'Magic Links' },
]

const activeTab = ref('totp')
const items = ref<NotifyPayload[]>([])
const now = ref(Date.now())

let pollTimer: ReturnType<typeof setInterval>
let clockTimer: ReturnType<typeof setInterval>

const totpItems  = computed(() => items.value.filter(i => i.type === 'totp'))
const pushItems  = computed(() => items.value.filter(i => i.type === 'push'))
const smsItems   = computed(() => items.value.filter(i => i.type === 'sms'))
const magicItems = computed(() => items.value.filter(i => i.type === 'magic_link'))

async function load() {
  try {
    const res = await fetch('/api/v1/notifications/all')
    if (res.ok) items.value = await res.json()
  } catch { /* server not reachable during dev */ }
}

function secondsLeft(expiresAt?: string): number {
  if (!expiresAt) return 0
  return Math.max(0, Math.floor((new Date(expiresAt).getTime() - now.value) / 1000))
}

function timerPercent(expiresAt?: string): number {
  if (!expiresAt) return 0
  const total = 30000
  const left = new Date(expiresAt).getTime() - now.value
  return Math.max(0, Math.min(100, (left / total) * 100))
}

function copy(text?: string) {
  if (text) navigator.clipboard.writeText(text)
}

async function useCode(item: NotifyPayload) {
  // Navigate to the login MFA page for this flow — user can paste the code there
  window.open(`/login/mfa?flow_id=${item.flow_id}`, '_blank')
}

async function approve(item: NotifyPayload) {
  await fetch(`/api/v1/flows/${item.flow_id}/approve`, { method: 'POST' })
  await load()
}

async function deny(item: NotifyPayload) {
  await fetch(`/api/v1/flows/${item.flow_id}/deny`, { method: 'POST' })
  await load()
}

onMounted(() => {
  load()
  pollTimer  = setInterval(load, 3000)
  clockTimer = setInterval(() => { now.value = Date.now() }, 1000)
})

onUnmounted(() => {
  clearInterval(pollTimer)
  clearInterval(clockTimer)
})
</script>
