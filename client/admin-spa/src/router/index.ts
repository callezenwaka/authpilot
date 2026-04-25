import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Users from '../views/Users.vue'
import Groups from '../views/Groups.vue'
import Sessions from '../views/Sessions.vue'
import Scim from '../views/Scim.vue'
import WsFed from '../views/WsFed.vue'
import Audit from '../views/Audit.vue'
import Config from '../views/Config.vue'
import Diff from '../views/Diff.vue'
import Callback from '../views/Callback.vue'
import { oidcEnabled, userManager } from '../auth'

const router = createRouter({
  history: createWebHistory('/admin/'),
  routes: [
    { path: '/',          component: Dashboard },
    { path: '/users',     component: Users },
    { path: '/groups',    component: Groups },
    { path: '/sessions',  component: Sessions },
    { path: '/scim',      component: Scim },
    { path: '/wsfed',     component: WsFed },
    { path: '/audit',     component: Audit },
    { path: '/config',    component: Config },
    { path: '/diff',      component: Diff },
    { path: '/callback',  component: Callback },
  ],
})

// When OIDC is enabled, redirect unauthenticated users to the IdP login.
router.beforeEach(async (to) => {
  if (!oidcEnabled || to.path === '/callback') return true
  const user = await userManager!.getUser()
  if (!user || user.expired) {
    await userManager!.signinRedirect()
    return false
  }
  return true
})

export default router
