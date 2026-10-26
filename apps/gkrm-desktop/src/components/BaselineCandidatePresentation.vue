<script setup lang="ts">
import type { BaselineCandidatePresentation } from '@/types/commands'

defineProps<{ presentation: BaselineCandidatePresentation }>()
</script>

<template>
  <span class="baseline-candidate-presentation">
    <span>Resource: {{ presentation.resourceLabel }};</span>
    <span v-if="presentation.version.state === 'declared'">
      Declared version: {{ presentation.version.value }};
    </span>
    <span v-else-if="presentation.version.state === 'declaredEmpty'">
      Version declaration: present with an empty value;
    </span>
    <span v-else>Version: not declared;</span>
    <span>Files: {{ presentation.fileCount }};</span>
    <span>Protected files: {{ presentation.protectedFileCount }};</span>
    <span>Editable files: {{ presentation.editableFileCount }};</span>
    <span>Retained blobs: {{ presentation.retainedBlobCount }};</span>
    <span>Retained bytes: {{ presentation.retainedBlobBytes }}.</span>
  </span>
</template>

<style scoped>
.baseline-candidate-presentation {
  display: grid;
  gap: 0.2rem;
}
</style>
