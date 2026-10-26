import { createRouter, createWebHashHistory } from 'vue-router'

import AboutView from '@/views/AboutView.vue'
import HistoryView from '@/views/HistoryView.vue'
import UpdateView from '@/views/UpdateView.vue'

/**
 * The update screen is the product: a folder, a package, a diff, and a list to answer.
 *
 * History is the other half of owning an installation: what earlier updates left behind, and the
 * only place recovery is performed. It is deliberately separate — the update screen never offers
 * to repair anything, and this one never offers to update.
 *
 * There is no recovery-first navigation guard any more because there is nowhere to navigate to.
 * Recovery-first is enforced where it always mattered — the trusted stores refuse to create,
 * submit, or apply while the durable overview is unclear, and the console resolves its single
 * primary action from the same state, so an unresolved workspace offers only the recovery check.
 */
export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', name: 'update', component: UpdateView },
    { path: '/history', name: 'history', component: HistoryView },
    { path: '/console', redirect: '/history' },
    { path: '/about', name: 'about', component: AboutView },
    { path: '/settings', redirect: '/about' },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})
