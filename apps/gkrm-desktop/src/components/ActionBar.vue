<template>
  <footer class="action-bar">
    <div class="action-bar__content"><slot /></div>
    <div class="action-bar__actions"><slot name="actions" /></div>
  </footer>
</template>

<style scoped>
.action-bar {
  display: flex;
  flex: none;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-24);
  padding: var(--space-16) var(--space-24);
  border-top: 1px solid var(--border);
  background: var(--surface);
}

.action-bar__content {
  display: grid;
  flex: 1;
  gap: var(--space-8);
  min-width: 0;
}

.action-bar__actions {
  display: flex;
  flex: none;
  align-items: center;
  gap: var(--space-8);
}

@media (max-width: 900px) {
  .action-bar {
    gap: var(--space-16);
    padding: var(--space-12) var(--space-16);
  }
}
</style>
