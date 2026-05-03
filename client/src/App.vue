<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="sidebar-logo">Fur<span>nace</span></div>
      <nav>
        <router-link to="/">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/></svg>
          Dashboard
        </router-link>
        <router-link to="/users">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/></svg>
          Users
        </router-link>
        <router-link to="/groups">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v1h8v-1zM6 8a2 2 0 11-4 0 2 2 0 014 0zM16 18v-1a5.97 5.97 0 00-.75-2.906A3.005 3.005 0 0119 15v1h-3zM4.75 14.094A5.97 5.97 0 004 17v1H1v-1a3 3 0 013.75-2.906z"/></svg>
          Groups
        </router-link>
        <router-link to="/sessions">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 3a1 1 0 000 2v8a2 2 0 002 2h2.586l-1.293 1.293a1 1 0 101.414 1.414L10 15.414l2.293 2.293a1 1 0 001.414-1.414L12.414 15H15a2 2 0 002-2V5a1 1 0 100-2H3zm11 4a1 1 0 10-2 0v4a1 1 0 102 0V7zm-3 1a1 1 0 10-2 0v3a1 1 0 102 0V8zM8 9a1 1 0 00-2 0v2a1 1 0 102 0V9z" clip-rule="evenodd"/></svg>
          Sessions
        </router-link>
        <router-link to="/audit">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h7a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h4a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd"/></svg>
          Audit Log
        </router-link>
        <div class="nav-section-label">Protocols</div>
        <router-link to="/scim">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z"/><path d="M3 7v3c0 1.657 3.134 3 7 3s7-1.343 7-3V7c0 1.657-3.134 3-7 3S3 8.657 3 7z"/><path d="M17 5c0 1.657-3.134 3-7 3S3 6.657 3 5s3.134-3 7-3 7 1.343 7 3z"/></svg>
          SCIM
        </router-link>
        <router-link to="/wsfed">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
          WS-Federation
        </router-link>
        <div class="nav-section-label">Access</div>
        <router-link to="/admins">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd"/></svg>
          Admins
        </router-link>
        <div class="nav-section-label">Developer</div>
        <router-link to="/diff">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z"/><path fill-rule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clip-rule="evenodd"/></svg>
          Token Diff
        </router-link>
        <router-link to="/config">
          <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/></svg>
          Config
        </router-link>
      </nav>
    </aside>
    <div class="main">
      <header class="topbar">
        <span class="topbar-title">{{ pageTitle }}</span>
        <div style="display:flex;align-items:center;gap:12px">
          <select
            v-if="tenants.length > 0"
            v-model="activeTenant"
            style="font-size:12px;padding:3px 8px;border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);color:var(--text)"
            title="Active tenant"
          >
            <option v-for="t in tenants" :key="t" :value="t">{{ t }}</option>
          </select>
          <button class="bell-btn" @click="notifyDialog?.open()" title="Notification Hub" aria-label="Open notification hub">
            <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a6 6 0 00-6 6v3.586l-.707.707A1 1 0 004 14h12a1 1 0 00.707-1.707L16 11.586V8a6 6 0 00-6-6zM10 18a3 3 0 01-3-3h6a3 3 0 01-3 3z"/></svg>
            <span v-if="notifyCount > 0" class="bell-badge">{{ notifyCount }}</span>
          </button>
          <a href="/login" style="font-size:12px;color:var(--text-muted);text-decoration:none">Login Simulator →</a>
          <button v-if="oidcEnabled" class="signout-btn" @click="signOut" title="Sign out">Sign out</button>
          <form v-else method="post" action="/admin/logout" style="margin:0">
            <button type="submit" class="signout-btn" title="Sign out">Sign out</button>
          </form>
        </div>
      </header>
      <router-view />
    </div>
  </div>

  <NotifyDialog ref="notifyDialog" />
</template>

<script setup lang="ts">
import { apiFetch, oidcEnabled, userManager } from './auth'
import { ref, computed, onMounted, provide } from 'vue'
import { useRoute } from 'vue-router'
import NotifyDialog from './components/NotifyDialog.vue'
import { useSSE } from './composables/useSSE'

const route = useRoute()

const tenants      = ref<string[]>([])
const activeTenant = ref('default')
const notifyDialog = ref<InstanceType<typeof NotifyDialog> | null>(null)

provide('activeTenant', activeTenant)

const notifyCount = ref(0)

async function fetchBadgeCount() {
  try {
    const res = await apiFetch('/api/v1/notifications/all')
    if (res.ok) {
      const items = await res.json()
      notifyCount.value = Array.isArray(items) ? items.length : 0
    }
  } catch { /* server unreachable */ }
}

useSSE({ flows: fetchBadgeCount })

async function loadTenants() {
  try {
    tenants.value = []
  } catch { /* ignore */ }
}

async function signOut() {
  await userManager?.signoutRedirect()
}

const pageTitle = computed(() => {
  switch (route.path) {
    case '/':         return 'Dashboard'
    case '/users':    return 'Users'
    case '/groups':   return 'Groups'
    case '/sessions': return 'Sessions'
    case '/audit':    return 'Audit Log'
    case '/scim':     return 'SCIM Provisioning'
    case '/wsfed':    return 'WS-Federation'
    case '/diff':     return 'Token Diff'
    case '/config':   return 'Configuration'
    case '/admins':   return 'Admins'
    default:          return 'Furnace'
  }
})

onMounted(() => {
  loadTenants()
  fetchBadgeCount()
})
</script>

<style scoped>
.nav-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 8px 10px;
  border: none;
  border-radius: var(--radius, 6px);
  background: none;
  color: var(--nav-text, #cbd5e1);
  font-size: 13.5px;
  text-align: left;
  cursor: pointer;
  margin-bottom: 2px;
  transition: background .15s, color .15s;
}
.nav-btn:hover { background: rgba(255,255,255,.07); color: #fff; }

.nav-badge {
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 700;
  background: #2563eb;
  color: #fff;
}

.bell-btn {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border: none;
  border-radius: var(--radius, 6px);
  background: none;
  color: var(--text-muted);
  cursor: pointer;
  transition: background .15s, color .15s;
}
.bell-btn:hover { background: var(--bg); color: var(--text); }

.bell-badge {
  position: absolute;
  top: 1px;
  right: 1px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 14px;
  height: 14px;
  padding: 0 3px;
  border-radius: 999px;
  font-size: 9px;
  font-weight: 700;
  background: #dc2626;
  color: #fff;
  line-height: 1;
  border: 2px solid #fff;
}
.bell-badge::after {
  content: '';
  position: absolute;
  inset: -4px;
  border-radius: 50%;
  background: #dc2626;
  opacity: 0;
  animation: badge-pulse 1.8s ease-out infinite;
}
@keyframes badge-pulse {
  0%   { transform: scale(0.4); opacity: 0.7; }
  70%  { transform: scale(1.6); opacity: 0; }
  100% { transform: scale(1.6); opacity: 0; }
}

.signout-btn {
  font-size: 12px;
  padding: 4px 10px;
  border: 1px solid var(--border);
  border-radius: var(--radius, 6px);
  background: none;
  color: var(--text-muted);
  cursor: pointer;
  transition: background .15s, color .15s;
}
.signout-btn:hover { background: var(--bg); color: var(--text); }
</style>
