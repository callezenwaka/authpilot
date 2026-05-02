<template>
  <div class="page">
    <div class="page-header">
      <h1>WS-Federation</h1>
    </div>

    <div class="stat-grid" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr));margin-bottom:24px">
      <div class="stat-card">
        <div class="label">Passive Endpoint</div>
        <div class="value" style="font-size:13px;font-weight:500;margin-top:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          <code>{{ protocolURL }}/wsfed</code>
        </div>
      </div>
      <div class="stat-card">
        <div class="label">Metadata Endpoint</div>
        <div class="value" style="font-size:13px;font-weight:500;margin-top:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          <code>{{ protocolURL }}/federationmetadata/…</code>
        </div>
      </div>
      <div class="stat-card">
        <div class="label">Token Type</div>
        <div class="value" style="font-size:13px;font-weight:500;margin-top:6px">SAML 1.1 / WS-Trust</div>
      </div>
      <div class="stat-card">
        <div class="label">Signing</div>
        <div class="value" style="font-size:13px;font-weight:500;margin-top:6px">RSA-SHA256 + exc-c14n</div>
      </div>
    </div>

    <!-- Sign-in flow reference -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <h2>Passive Sign-In Flow</h2>
      </div>
      <div class="card-body" style="padding:18px">
        <ol style="margin:0;padding-left:20px;line-height:2;font-size:13px">
          <li>Relying party redirects browser to <code>{{ protocolURL }}/wsfed?wa=wsignin1.0&amp;wtrealm=&lt;realm&gt;&amp;wreply=&lt;url&gt;</code></li>
          <li>Furnace validates <code>wtrealm</code>, creates a flow, and redirects to <code>/login</code></li>
          <li>User completes login; Furnace creates a session and redirects back to <code>/wsfed</code> with <code>wsfed_flow_id</code></li>
          <li>Furnace builds a signed WS-Trust RSTR (SAML 1.1 assertion) and auto-submits it to <code>wreply</code></li>
        </ol>
      </div>
    </div>

    <!-- Sign-out flow reference -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <h2>Passive Sign-Out Flow</h2>
      </div>
      <div class="card-body" style="padding:18px">
        <ol style="margin:0;padding-left:20px;line-height:2;font-size:13px">
          <li>Relying party redirects browser to <code>{{ protocolURL }}/wsfed?wa=wsignout1.0&amp;wreply=&lt;url&gt;</code></li>
          <li>Furnace invalidates all sessions</li>
          <li>Browser is redirected to <code>wreply</code>, or a sign-out confirmation page is shown if <code>wreply</code> is absent</li>
        </ol>
      </div>
    </div>

    <!-- Metadata viewer -->
    <div class="card" style="margin-bottom:20px">
      <div class="card-header">
        <h2>Federation Metadata</h2>
        <div style="display:flex;gap:8px;align-items:center">
          <span :class="['badge', metaStatus === 'ok' ? 'badge-green' : metaStatus === 'error' ? 'badge-red' : 'badge-gray']">
            {{ metaStatus === 'ok' ? 'reachable' : metaStatus === 'error' ? 'unreachable' : 'checking…' }}
          </span>
          <a
            :href="`${protocolURL}/federationmetadata/2007-06/federationmetadata.xml`"
            target="_blank"
            class="btn btn-ghost btn-sm"
          >Open ↗</a>
          <button class="btn btn-ghost btn-sm" @click="loadMetadata">Refresh</button>
        </div>
      </div>
      <div class="card-body" style="padding:18px">
        <pre v-if="metadataXML" style="font-size:11px;margin:0;overflow-x:auto;white-space:pre-wrap;word-break:break-all">{{ metadataXML }}</pre>
        <div v-else class="empty" style="padding:24px">
          {{ metaStatus === 'checking' ? `Loading metadata from ${protocolURL}…` : `Could not reach ${protocolURL}. Is the protocol server running?` }}
        </div>
      </div>
    </div>

    <!-- Quick links -->
    <div class="card">
      <div class="card-header"><h2>Quick Links</h2></div>
      <div class="card-body" style="padding:18px">
        <table style="width:auto">
          <tbody>
            <tr>
              <td style="padding:6px 12px 6px 0;color:var(--text-muted);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap">Info page</td>
              <td style="padding:6px 0">
                <a :href="`${protocolURL}/wsfed`" target="_blank" style="font-size:13px;color:var(--primary)">{{ protocolURL }}/wsfed</a>
              </td>
            </tr>
            <tr>
              <td style="padding:6px 12px 6px 0;color:var(--text-muted);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap">Metadata XML</td>
              <td style="padding:6px 0">
                <a :href="`${protocolURL}/federationmetadata/2007-06/federationmetadata.xml`" target="_blank" style="font-size:13px;color:var(--primary)">{{ protocolURL }}/federationmetadata/2007-06/federationmetadata.xml</a>
              </td>
            </tr>
            <tr>
              <td style="padding:6px 12px 6px 0;color:var(--text-muted);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap">Sign-in</td>
              <td style="padding:6px 0">
                <code style="font-size:12px">{{ protocolURL }}/wsfed?wa=wsignin1.0&amp;wtrealm=&lt;realm&gt;&amp;wreply=&lt;url&gt;</code>
              </td>
            </tr>
            <tr>
              <td style="padding:6px 12px 6px 0;color:var(--text-muted);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap">Sign-out</td>
              <td style="padding:6px 0">
                <code style="font-size:12px">{{ protocolURL }}/wsfed?wa=wsignout1.0&amp;wreply=&lt;url&gt;</code>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from '../auth'
import { ref, onMounted } from 'vue'

const metadataXML = ref('')
const metaStatus = ref<'checking' | 'ok' | 'error'>('checking')
const protocolURL = ref('http://localhost:8026')

async function loadProtocolURL() {
  try {
    const res = await apiFetch('/api/v1/config')
    const cfg = await res.json()
    if (cfg.protocol_url) protocolURL.value = cfg.protocol_url
  } catch { /* keep default */ }
}

async function loadMetadata() {
  metaStatus.value = 'checking'
  metadataXML.value = ''
  try {
    const res = await fetch(
      `${protocolURL.value}/federationmetadata/2007-06/federationmetadata.xml`,
      { signal: AbortSignal.timeout(3000) }
    )
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    metadataXML.value = await res.text()
    metaStatus.value = 'ok'
  } catch {
    metaStatus.value = 'error'
  }
}

onMounted(async () => {
  await loadProtocolURL()
  await loadMetadata()
})
</script>
