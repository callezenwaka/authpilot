import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../views/Dashboard.vue'
import Users from '../views/Users.vue'
import Groups from '../views/Groups.vue'
import Sessions from '../views/Sessions.vue'
import Scim from '../views/Scim.vue'
import WsFed from '../views/WsFed.vue'

const router = createRouter({
  history: createWebHistory('/admin/'),
  routes: [
    { path: '/',         component: Dashboard },
    { path: '/users',    component: Users },
    { path: '/groups',   component: Groups },
    { path: '/sessions', component: Sessions },
    { path: '/scim',     component: Scim },
    { path: '/wsfed',    component: WsFed },
  ],
})

export default router
