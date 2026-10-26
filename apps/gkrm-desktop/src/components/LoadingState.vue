<script setup lang="ts">
defineProps<{
  label: string
}>()
</script>

<template>
  <div class="loading-state" role="status" aria-live="polite">
    <span class="loading-dot" aria-hidden="true"></span>
    <span>{{ label }}</span>
  </div>
</template>

<style scoped>
.loading-state {
  display: inline-flex;
  gap: var(--space-8);
  align-items: center;
  color: var(--text-muted);
  font-size: 0.875rem;
}

.loading-dot {
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: var(--accent);
}
</style>
