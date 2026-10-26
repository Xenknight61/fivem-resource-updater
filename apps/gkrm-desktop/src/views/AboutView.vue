<script setup lang="ts">
import { useAppStore } from '@/stores/app'

const appStore = useAppStore()

function platformLabel(platform: string) {
  const labels: Record<string, string> = {
    windows: 'Windows',
    linux: 'Linux',
    macos: 'macOS',
    unknown: 'Unknown',
  }
  return labels[platform] ?? 'Unknown'
}

function buildProfileLabel(profile: string) {
  return profile === 'release' ? 'Release build' : 'Development build'
}

/**
 * What the application will and will not do on its own.
 *
 * Each one is a promise the operator can hold the product to, written as the guarantee rather
 * than the feature: the point of this page is to say what runs without being asked, which is
 * nothing.
 */
const principles = [
  { term: 'Local and offline', detail: 'No server, no account, no network calls.' },
  { term: 'Explicit apply', detail: 'Your installation changes only when you press a button.' },
  { term: 'Backed up first', detail: 'Every file it overwrites is copied and journalled first.' },
  { term: 'Explicit recovery', detail: 'Recovery is inspected and started by you, never on its own.' },
  { term: 'No automatic cleanup', detail: 'Update and recovery evidence is kept until you retire it.' },
  { term: 'No updater', detail: 'The application never downloads or installs its own updates.' },
]
</script>

<template>
  <section class="about-view" aria-labelledby="about-heading">
    <header class="about-header">
      <p class="eyebrow">About</p>
      <h1 id="about-heading">Resource Manager</h1>
      <p class="lede">
        A local desktop application for inspecting, reviewing, updating, and recovering FiveM
        resources safely.
      </p>
    </header>

    <dl v-if="appStore.info" class="metadata-list" aria-label="Version information">
      <div>
        <dt>Application version</dt>
        <dd>{{ appStore.info.appVersion }}</dd>
      </div>
      <div>
        <dt>Core version</dt>
        <dd>{{ appStore.info.coreVersion }}</dd>
      </div>
      <div>
        <dt>Platform</dt>
        <dd>{{ platformLabel(appStore.info.platform) }}</dd>
      </div>
      <div>
        <dt>Build</dt>
        <dd>{{ buildProfileLabel(appStore.info.buildProfile) }}</dd>
      </div>
    </dl>

    <section class="principles" aria-labelledby="principles-heading">
      <h2 id="principles-heading">What it does on its own</h2>
      <ul>
        <li v-for="principle in principles" :key="principle.term">
          <strong>{{ principle.term }}</strong>
          <span>{{ principle.detail }}</span>
        </li>
      </ul>
    </section>
  </section>
</template>

<style scoped>
/* The frame gives its working screens no padding, because the console draws its own edges. A
   document page has to supply its own, or its text sits flush against the window. */
.about-view {
  display: grid;
  align-content: start;
  gap: var(--space-24);
  width: min(100%, 720px);
  min-height: 0;
  padding: var(--space-32) var(--space-24);
  margin: 0 auto;
  overflow-y: auto;
}

.about-header h1 {
  margin: 0;
  font-size: var(--text-page-title);
  line-height: 1.2;
}

.lede {
  max-width: 58ch;
  margin: var(--space-8) 0 0;
  color: var(--text-muted);
  line-height: 1.55;
}

.metadata-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 0;
  margin: 0;
  background: var(--border);
  overflow: hidden;
}

.metadata-list div {
  display: grid;
  gap: var(--space-4);
  padding: var(--space-12) var(--space-16);
  background: var(--surface);
}

.metadata-list dt {
  color: var(--text-muted);
  font-size: 0.76rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.metadata-list dd {
  margin: 0;
  font-size: 0.94rem;
  font-weight: 620;
  font-variant-numeric: tabular-nums;
}

.principles h2 {
  margin: 0 0 var(--space-12);
  font-size: var(--text-section);
}

.principles ul {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: var(--space-12);
  padding: 0;
  margin: 0;
  list-style: none;
}

.principles li {
  display: grid;
  gap: var(--space-4);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-12) var(--space-16);
  background: var(--surface);
}

.principles strong {
  font-size: 0.9rem;
}

.principles span {
  color: var(--text-muted);
  font-size: 0.86rem;
  line-height: 1.5;
}</style>
