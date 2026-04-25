<template>
  <div class="page">
    <div class="page-header">
      <h1>Token Diff</h1>
    </div>

    <div class="card" style="margin-bottom:20px">
      <div class="card-header"><h2>Compare Tokens</h2></div>
      <div class="card-body">
        <div class="form-group">
          <label>Furnace Token (JWT)</label>
          <textarea v-model="furnaceToken" rows="3" placeholder="eyJ…" style="font-family:monospace;font-size:12px;resize:vertical" />
        </div>
        <div class="form-group">
          <label>Provider Token (JWT)</label>
          <textarea v-model="providerToken" rows="3" placeholder="eyJ…" style="font-family:monospace;font-size:12px;resize:vertical" />
        </div>
        <div class="form-group">
          <label>Flow ID (optional — for context correlation)</label>
          <input v-model="flowID" placeholder="flow_…" />
        </div>
        <div class="form-actions">
          <span v-if="error" class="error-msg" style="align-self:center">{{ error }}</span>
          <button class="btn btn-primary" @click="compare" :disabled="loading">
            {{ loading ? 'Comparing…' : 'Compare' }}
          </button>
        </div>
      </div>
    </div>

    <div v-if="result">
      <!-- Summary -->
      <div style="margin-bottom:16px;display:flex;gap:10px;align-items:center">
        <span v-if="result.differences.length === 0" class="badge badge-green" style="font-size:13px;padding:4px 12px">
          Tokens are identical
        </span>
        <span v-else class="badge badge-yellow" style="font-size:13px;padding:4px 12px">
          {{ result.differences.length }} difference{{ result.differences.length !== 1 ? 's' : '' }} found
        </span>
      </div>

      <!-- Differences table -->
      <div v-if="result.differences.length" class="card" style="margin-bottom:20px">
        <div class="card-header"><h2>Differences</h2></div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Claim</th>
                <th>Furnace value</th>
                <th>Provider value</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="d in result.differences" :key="d.path">
                <td><code>{{ d.path }}</code></td>
                <td>
                  <span v-if="d.furnace_value !== null && d.furnace_value !== undefined" style="font-family:monospace;font-size:12px">
                    {{ JSON.stringify(d.furnace_value) }}
                  </span>
                  <span v-else class="badge badge-gray">—</span>
                </td>
                <td>
                  <span v-if="d.provider_value !== null && d.provider_value !== undefined" style="font-family:monospace;font-size:12px">
                    {{ JSON.stringify(d.provider_value) }}
                  </span>
                  <span v-else class="badge badge-gray">—</span>
                </td>
                <td style="font-size:12px;color:var(--text-muted)">{{ d.note }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Side-by-side claims -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
        <div class="card">
          <div class="card-header"><h2>Furnace Claims</h2></div>
          <div class="card-body">
            <pre style="font-size:12px;margin:0;overflow-x:auto;white-space:pre-wrap">{{ formatJSON(result.furnace_token) }}</pre>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><h2>Provider Claims</h2></div>
          <div class="card-body">
            <pre style="font-size:12px;margin:0;overflow-x:auto;white-space:pre-wrap">{{ formatJSON(result.provider_token) }}</pre>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref } from 'vue'

interface ClaimDiff {
  path: string
  furnace_value: any
  provider_value: any
  note: string
}

interface DiffResult {
  furnace_token: Record<string, any>
  provider_token: Record<string, any>
  differences: ClaimDiff[]
}

const furnaceToken = ref('')
const providerToken = ref('')
const flowID = ref('')
const loading = ref(false)
const error = ref('')
const result = ref<DiffResult | null>(null)

async function compare() {
  error.value = ''
  result.value = null
  const ap = furnaceToken.value.trim()
  const pv = providerToken.value.trim()
  if (!ap || !pv) {
    error.value = 'Both tokens are required.'
    return
  }
  loading.value = true
  try {
    const params = new URLSearchParams({ furnace_token: ap, provider_token: pv })
    if (flowID.value.trim()) params.set('flow_id', flowID.value.trim())
    const res = await apiFetch('/api/v1/debug/token-compare?' + params.toString())
    const data = await res.json()
    if (!res.ok) {
      throw new Error(data?.error?.message ?? `${res.status}`)
    }
    result.value = data
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function formatJSON(obj: any) {
  return JSON.stringify(obj, null, 2)
}
</script>
