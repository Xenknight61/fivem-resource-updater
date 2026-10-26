<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, RouterView, useRoute } from 'vue-router'

import { navigationItems } from '@/app/navigation'
import LoadingState from '@/components/LoadingState.vue'
import { useAppStore } from '@/stores/app'
import { useRecoveryStore } from '@/stores/recovery'

/**
 * A slim frame around a single working screen.
 *
 * It carries identity, the application-level error surface, and the three destinations: the
 * update itself, what earlier updates left behind, and the application's own details.
 */
const appStore = useAppStore()
const recoveryStore = useRecoveryStore()
const route = useRoute()

/**
 * The working screens surface failures beside the control that produced them. Announcing the same
 * one again in the frame would read as two separate failures, so the frame only reports what the
 * screen underneath is not already showing.
 */
const showGlobalError = computed(() => {
  const error = appStore.error
  if (error === null) return false
  return ![recoveryStore.error, recoveryStore.overviewError].includes(error)
})
</script>

<template>
  <a class="skip-link" href="#main-content">Skip to content</a>
  <div class="app-shell">
    <header class="title-bar">
      <span class="brand-name">FiveM Resource <span>Updater</span></span>
      <nav class="quick-nav" aria-label="Primary">
        <RouterLink
          v-for="item in navigationItems"
          :key="item.path"
          :to="item.path"
          :aria-current="route.path === item.path ? 'page' : undefined"
        >
          {{ item.name }}
        </RouterLink>
      </nav>
    </header>

    <LoadingState
      v-if="appStore.initializing"
      class="app-initializing"
      label="Loading application information"
    />

    <div v-if="showGlobalError" class="error-banner" role="alert">
      <span>{{ appStore.error?.message }}</span>
      <button type="button" @click="appStore.dismissError">Dismiss</button>
    </div>

    <main id="main-content" class="main-region" tabindex="-1">
      <RouterView />
    </main>
  </div>
</template>

<style scoped>
/* Exactly the window, never taller. A working screen scrolls its own middle, so the header it
   navigates by and the buttons it acts through stay where they were put. */
.app-shell {
  display: flex;
  flex-direction: column;
  min-width: 760px;
  height: 100vh;
  overflow: hidden;
  background: var(--background);
}

.skip-link {
  position: fixed;
  top: var(--space-12);
  left: var(--space-12);
  z-index: 10;
  transform: translateY(-160%);
  border-radius: var(--radius-md);
  background: var(--accent);
  color: #06100b;
  padding: var(--space-8) var(--space-12);
  font-weight: 700;
  text-decoration: none;
}

.skip-link:focus {
  transform: translateY(0);
}

.title-bar {
  display: flex;
  align-items: center;
  gap: var(--space-12);
  border-bottom: 1px solid var(--border);
  padding: var(--space-8) var(--space-16);
  background: var(--surface);
}

/* A wordmark, not a logo. The product name is the only identity the frame carries; a coloured
   badge beside it competed with the accent colour, which already means "official/vendor". */
.brand-name {
  font-size: 0.9rem;
  font-weight: 700;
  letter-spacing: 0.01em;
}

.brand-name span {
  color: var(--text-muted);
  font-weight: 500;
}

.quick-nav {
  display: flex;
  gap: var(--space-4);
  margin-left: auto;
}

.quick-nav a {
  border-radius: var(--radius-md);
  padding: 6px var(--space-12);
  color: var(--text-muted);
  font-size: 0.84rem;
  text-decoration: none;
}

.quick-nav a[aria-current='page'] {
  background: var(--surface-raised);
  color: var(--text);
}

.quick-nav a:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}

.main-region {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  min-width: 0;
}

.app-initializing,
.error-banner {
  margin: var(--space-12) var(--space-16) 0;
}

.error-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-16);
  border: 1px solid var(--danger);
  border-radius: var(--radius-md);
  padding: var(--space-12);
  background: rgba(227, 93, 91, 0.08);
}

.error-banner button {
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-8) var(--space-12);
  background: var(--surface-raised);
  color: var(--text);
}</style>
