<script setup lang="ts">
defineProps<{ label: string; divided?: boolean }>()
</script>

<template>
  <details class="disclosure" :class="{ 'disclosure--divided': divided }">
    <summary>{{ label }}</summary>
    <div class="disclosure__body"><slot /></div>
  </details>
</template>

<style scoped>
.disclosure > summary {
  cursor: pointer;
  color: var(--text-muted);
  font-size: var(--text-caption);
  line-height: 1.5;
}

.disclosure > summary:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 3px;
}

.disclosure__body {
  padding-top: var(--space-12);
}

.disclosure--divided {
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}

.disclosure--divided > summary {
  padding: var(--space-16) 0;
}

.disclosure--divided .disclosure__body {
  padding: 0 0 var(--space-16);
}
</style>
