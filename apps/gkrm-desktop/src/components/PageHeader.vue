<script setup lang="ts">
defineProps<{
  headingId: string
  title: string
  description?: string
  eyebrow?: string
  document?: boolean
}>()
</script>

<template>
  <header class="product-header" :class="{ 'product-header--document': document }">
    <div class="product-header__heading">
      <p v-if="eyebrow" class="product-header__eyebrow">{{ eyebrow }}</p>
      <h1 :id="headingId">{{ title }}</h1>
      <p v-if="description" class="product-header__description">{{ description }}</p>
    </div>
    <div v-if="$slots.actions" class="product-header__actions"><slot name="actions" /></div>
    <div v-if="$slots.default" class="product-header__body"><slot /></div>
  </header>
</template>

<style scoped>
.product-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-24);
  margin: 0;
  padding: var(--space-20) var(--space-24);
  border-bottom: 1px solid var(--border);
}

.product-header h1 {
  margin: 0;
  font-size: var(--text-page-title);
  line-height: 1.3;
  letter-spacing: -0.02em;
}

.product-header__description {
  max-width: 68ch;
  margin: var(--space-8) 0 0;
  color: var(--text-muted);
  font-size: var(--text-body);
  line-height: 1.6;
}

.product-header__actions {
  flex: none;
  font-size: var(--text-body);
}

.product-header__eyebrow {
  margin: 0 0 var(--space-16);
  color: var(--text-muted);
  font-size: var(--text-caption);
}

.product-header--document {
  flex-direction: column;
  align-items: flex-start;
  gap: var(--space-16);
  padding: 0;
  border: 0;
}

.product-header__body {
  width: 100%;
}

@media (max-width: 900px) {
  .product-header:not(.product-header--document) {
    padding: var(--space-16);
  }
}
</style>
