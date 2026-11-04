<script setup lang="ts">
withDefaults(defineProps<{
  tone?: 'neutral' | 'success' | 'warning' | 'danger'
  announce?: boolean
}>(), { tone: 'neutral', announce: true })
</script>

<template>
  <div class="status-notice" :class="`status-notice--${tone}`" :role="announce ? (tone === 'danger' ? 'alert' : 'status') : undefined">
    <div class="status-notice__content"><slot /></div>
    <div v-if="$slots.actions" class="status-notice__actions"><slot name="actions" /></div>
  </div>
</template>

<style scoped>
.status-notice {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-16);
  padding: var(--space-12) var(--space-24);
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  font-size: var(--text-body);
  line-height: 1.5;
}

.status-notice__content {
  min-width: 0;
}

.status-notice__actions {
  display: flex;
  flex: none;
  align-items: center;
  gap: var(--space-8);
}

.status-notice--neutral {
  color: var(--text-muted);
}

.status-notice--success {
  border-left: 3px solid var(--success);
}

.status-notice--warning {
  border-left: 3px solid var(--warning);
}

.status-notice--danger {
  border-left: 3px solid var(--danger);
}

@media (max-width: 900px) {
  .status-notice {
    padding: var(--space-12) var(--space-16);
  }
}
</style>
