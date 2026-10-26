<script setup lang="ts">
defineProps<{
  title: string
  description: string
}>()
</script>

<template>
  <section class="empty-state" aria-live="polite">
    <h2>{{ title }}</h2>
    <p>{{ description }}</p>
  </section>
</template>

<style scoped>
.empty-state {
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--surface);
  padding: var(--space-24);
}

.empty-state h2 {
  margin: 0 0 var(--space-8);
  font-size: 1rem;
}

.empty-state p {
  margin: 0;
  color: var(--text-muted);
  line-height: 1.5;
}
</style>
