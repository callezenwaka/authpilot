<template>
  <div style="padding:2rem;color:var(--text-muted)">Completing sign in…</div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { userManager } from '../auth'

const router = useRouter()

onMounted(async () => {
  if (userManager) {
    await userManager.signinRedirectCallback()
  }
  router.push('/')
})
</script>
