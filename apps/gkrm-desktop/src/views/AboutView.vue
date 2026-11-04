<script setup lang="ts">
import { useAppStore } from '@/stores/app'
import Disclosure from '@/components/Disclosure.vue'
import PageHeader from '@/components/PageHeader.vue'

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
const principleGroups = [
  {
    title: 'Your files',
    items: [
      { term: 'Review before applying', detail: 'See what changes and choose which of your edits to keep before anything is written.' },
      { term: 'Backed up first', detail: 'Every file it overwrites is copied and journalled first.' },
      { term: 'Recovery on your terms', detail: 'Inspect and start recovery yourself. It never runs on its own.' },
    ],
  },
  {
    title: 'Your control',
    items: [
      { term: 'Local and offline', detail: 'No server, no account, no network calls. Your resources stay on your computer.' },
      { term: 'Storage you manage', detail: 'Backups and update records are kept. Only copies nothing needs can be released by you.' },
      { term: 'No automatic app updates', detail: 'The application never downloads or installs its own updates.' },
    ],
  },
]
</script>

<template>
  <section class="about-view" aria-labelledby="about-heading">
    <PageHeader class="about-header" heading-id="about-heading" title="FiveM Resource Updater" eyebrow="About" description="Update your resources. Keep the work you put into them." document>
      <p class="intro">Compare your installation with a new package, review the changes, and apply the update with a backup of every file it replaces.</p>
      <div class="about-actions">
        <a class="button-link" href="#/">Update a resource</a>
        <a class="text-link" href="#/history">View history</a>
      </div>
    </PageHeader>

    <Disclosure class="build-details" :label="appStore.info ? `Version ${appStore.info.appVersion} · Build details` : 'Application information'" divided>
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
      <p v-else class="metadata-unavailable">Version information is not available in this session.</p>
    </Disclosure>

    <section class="principles" aria-labelledby="principles-heading">
      <h2 id="principles-heading">Built around your installation</h2>
      <div class="principle-groups">
        <section v-for="group in principleGroups" :key="group.title" :aria-label="group.title">
          <h3>{{ group.title }}</h3>
          <ul>
            <li v-for="principle in group.items" :key="principle.term">
              <strong>{{ principle.term }}</strong>
              <span>{{ principle.detail }}</span>
            </li>
          </ul>
        </section>
      </div>
    </section>
    <footer class="about-footer">Works with the installation and packages you choose. Nothing runs without you starting it.</footer>
  </section>
</template>

<style scoped>
.about-view {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  min-width: 0;
  gap: var(--space-32);
  padding: var(--space-32) max(var(--space-24), calc((100% - 880px) / 2));
  overflow-y: auto;
}

.about-view > * {
  flex: none;
}

.intro {
  max-width: 64ch;
  margin: var(--space-8) 0 0;
  color: var(--text-muted);
  font-size: 0.86rem;
  line-height: 1.7;
}

.about-actions {
  display: flex;
  gap: var(--space-20);
  align-items: center;
  margin-top: var(--space-24);
  font-size: 0.84rem;
}

.about-actions .button-link {
  border-color: var(--control-border);
  font-weight: 600;
}

.about-actions .text-link {
  color: var(--text-muted);
  font-weight: 500;
}

.metadata-list {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--space-16);
  margin: 0;
  padding: 0 0 var(--space-20);
}

.metadata-list div {
  display: grid;
  gap: var(--space-8);
  align-content: start;
}

.metadata-list dt {
  color: var(--text-muted);
  font-size: 0.76rem;
}

.metadata-list dd {
  margin: 0;
  color: var(--text);
  font-size: 0.86rem;
  font-variant-numeric: tabular-nums;
}

.metadata-unavailable {
  margin: 0 0 var(--space-16);
  color: var(--text-muted);
  font-size: 0.84rem;
}

.principles h2 {
  margin: 0 0 var(--space-24);
  font-size: var(--text-section);
  font-weight: 600;
}

.principle-groups {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--space-32);
}

.principle-groups h3 {
  margin: 0 0 var(--space-8);
  color: var(--text-muted);
  font-size: 0.76rem;
  font-weight: 500;
}

.principles ul {
  display: grid;
  padding: 0;
  margin: 0;
  list-style: none;
}

.principles li {
  display: grid;
  gap: var(--space-8);
  align-content: start;
  padding: var(--space-16) 0;
  border-bottom: 1px solid var(--border);
}

.principles strong {
  font-size: 0.86rem;
  font-weight: 600;
}

.principles span {
  color: var(--text-muted);
  font-size: 0.84rem;
  line-height: 1.6;
}

.about-footer {
  margin-top: auto;
  padding-top: var(--space-8);
  color: var(--text-muted);
  font-size: 0.78rem;
  line-height: 1.6;
}

@media (max-width: 900px) {
  .about-view {
    gap: var(--space-24);
    padding: var(--space-24);
  }
  .metadata-list {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .principle-groups {
    gap: var(--space-24);
  }
}
</style>
