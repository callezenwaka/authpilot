<template>
  <div class="page">
    <div class="page-header">
      <h1>Configuration</h1>
    </div>

    <!-- Token TTLs -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <h2>Token Lifetimes</h2>
        <span class="badge badge-gray">live — no restart required</span>
      </div>
      <div class="card-body">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px">
          <div class="form-group" style="margin:0">
            <label>Access token TTL (seconds)</label>
            <input type="number" v-model.number="ttls.access_token_ttl" min="1" />
          </div>
          <div class="form-group" style="margin:0">
            <label>ID token TTL (seconds)</label>
            <input type="number" v-model.number="ttls.id_token_ttl" min="1" />
          </div>
          <div class="form-group" style="margin:0">
            <label>Refresh token TTL (seconds)</label>
            <input type="number" v-model.number="ttls.refresh_token_ttl" min="1" />
          </div>
        </div>
        <div class="form-actions">
          <span v-if="ttlSuccess" class="badge badge-green" style="align-self:center">Saved</span>
          <span v-if="ttlError" class="error-msg" style="align-self:center">{{ ttlError }}</span>
          <button class="btn btn-primary" @click="saveTTLs" :disabled="ttlSaving">
            {{ ttlSaving ? 'Saving…' : 'Save' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Provider Personality -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <h2>Provider Personality</h2>
        <span class="badge badge-gray">restart required to change</span>
      </div>
      <div class="card-body">
        <p style="margin:0 0 14px;font-size:13px;color:var(--text-muted)">
          The active personality shapes issued JWT claim names to match a real provider.
          Set <code>FURNACE_PROVIDER</code> or <code>provider:</code> in your YAML config and restart.
        </p>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px">
          <div
            v-for="p in personalities"
            :key="p.id"
            :class="['personality-card', p.id === activePersonality ? 'personality-active' : '']"
          >
            <div style="font-weight:600;font-size:13px">{{ p.name }}</div>
            <code style="font-size:11px;color:var(--text-muted)">{{ p.id }}</code>
          </div>
        </div>
        <p v-if="activePersonality" style="margin:14px 0 0;font-size:12px;color:var(--text-muted)">
          Active: <strong>{{ activePersonality }}</strong> — change by setting
          <code>FURNACE_PROVIDER=&lt;id&gt;</code> and restarting.
        </p>
      </div>
    </div>

    <!-- Admin API Key -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <h2>Admin API Key</h2>
        <span class="badge badge-gray">restart required to change</span>
      </div>
      <div class="card-body">
        <p style="margin:0 0 14px;font-size:13px;color:var(--text-muted)">
          Use this key to access the admin API directly (e.g. <code>curl</code>, CI scripts).
          Set <code>FURNACE_API_KEY</code> env var to persist this key across restarts.
        </p>
        <div class="key-row">
          <code class="key-display">{{ keyVisible ? adminApiKey : maskedKey }}</code>
          <button class="btn btn-ghost btn-sm" @click="keyVisible = !keyVisible">
            {{ keyVisible ? 'Hide' : 'Show' }}
          </button>
          <button class="btn btn-ghost btn-sm" @click="copyKey">
            {{ keyCopied ? 'Copied!' : 'Copy' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Session Hash Key -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <h2>Session Hash Key</h2>
        <span class="badge badge-gray">restart required to change</span>
      </div>
      <div class="card-body">
        <p style="margin:0 0 14px;font-size:13px;color:var(--text-muted)">
          Signs login session cookies. Auto-generated on first start and stored automatically when a volume is present.
          Copy this value and set <code>FURNACE_SESSION_HASH_KEY</code> only if you need sessions to survive a full volume wipe (e.g. migrating to a new server).
        </p>
        <div class="key-row">
          <code class="key-display">{{ sessionKeyVisible ? sessionHashKey : maskedSessionKey }}</code>
          <button class="btn btn-ghost btn-sm" @click="sessionKeyVisible = !sessionKeyVisible">
            {{ sessionKeyVisible ? 'Hide' : 'Show' }}
          </button>
          <button class="btn btn-ghost btn-sm" @click="copySessionKey">
            {{ sessionKeyCopied ? 'Copied!' : 'Copy' }}
          </button>
        </div>
      </div>
    </div>

    <div v-if="loadError" class="error-msg">{{ loadError }}</div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref, computed, onMounted } from 'vue'

const adminApiKey = window.__FURNACE__?.apiKey ?? ''
const keyVisible  = ref(false)
const keyCopied   = ref(false)

const maskedKey = computed(() =>
  adminApiKey ? adminApiKey.slice(0, 8) + '•'.repeat(Math.max(0, adminApiKey.length - 8)) : '—'
)

async function copyKey() {
  if (!adminApiKey) return
  await navigator.clipboard.writeText(adminApiKey)
  keyCopied.value = true
  setTimeout(() => { keyCopied.value = false }, 2000)
}

const sessionHashKey    = window.__FURNACE__?.sessionHashKey ?? ''
const sessionKeyVisible = ref(false)
const sessionKeyCopied  = ref(false)

const maskedSessionKey = computed(() =>
  sessionHashKey ? sessionHashKey.slice(0, 8) + '•'.repeat(Math.max(0, sessionHashKey.length - 8)) : '—'
)

async function copySessionKey() {
  if (!sessionHashKey) return
  await navigator.clipboard.writeText(sessionHashKey)
  sessionKeyCopied.value = true
  setTimeout(() => { sessionKeyCopied.value = false }, 2000)
}

interface TTLs {
  access_token_ttl: number | null
  id_token_ttl: number | null
  refresh_token_ttl: number | null
}

interface Personality {
  id: string
  name: string
}

const ttls = ref<TTLs>({ access_token_ttl: null, id_token_ttl: null, refresh_token_ttl: null })
const ttlSaving = ref(false)
const ttlSuccess = ref(false)
const ttlError = ref('')
const loadError = ref('')

const activePersonality = ref('')
const personalities: Personality[] = [
  { id: 'default',          name: 'Furnace Default' },
  { id: 'okta',             name: 'Okta' },
  { id: 'azure-ad',         name: 'Azure AD / Entra ID' },
  { id: 'google-workspace', name: 'Google Workspace' },
  { id: 'google',           name: 'Google' },
  { id: 'github',           name: 'GitHub' },
  { id: 'onelogin',         name: 'OneLogin' },
]

async function loadConfig() {
  try {
    const res = await apiFetch('/api/v1/config')
    if (!res.ok) throw new Error(`${res.status}`)
    const data = await res.json()
    ttls.value = {
      access_token_ttl:  data.tokens?.access_token_ttl  ?? null,
      id_token_ttl:      data.tokens?.id_token_ttl      ?? null,
      refresh_token_ttl: data.tokens?.refresh_token_ttl ?? null,
    }
    activePersonality.value = data.provider ?? ''
  } catch (e: any) {
    loadError.value = `Failed to load config: ${e.message}`
  }
}

async function saveTTLs() {
  ttlSaving.value = true
  ttlSuccess.value = false
  ttlError.value = ''
  try {
    const body: any = { tokens: {} }
    if (ttls.value.access_token_ttl != null)  body.tokens.access_token_ttl  = ttls.value.access_token_ttl
    if (ttls.value.id_token_ttl != null)      body.tokens.id_token_ttl      = ttls.value.id_token_ttl
    if (ttls.value.refresh_token_ttl != null) body.tokens.refresh_token_ttl = ttls.value.refresh_token_ttl
    const res = await apiFetch('/api/v1/config', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!res.ok) {
      const err = await res.json()
      throw new Error(err?.error?.message ?? `${res.status}`)
    }
    ttlSuccess.value = true
    setTimeout(() => { ttlSuccess.value = false }, 2500)
  } catch (e: any) {
    ttlError.value = e.message
  } finally {
    ttlSaving.value = false
  }
}

onMounted(loadConfig)
</script>

<style scoped>
.key-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}
.key-display {
  flex: 1;
  font-size: 13px;
  word-break: break-all;
  color: var(--text);
  user-select: all;
}
.personality-card {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  cursor: default;
  transition: border-color .15s;
}
.personality-active {
  border-color: var(--primary);
  background: #eff6ff;
}
</style>
