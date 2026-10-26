<script setup lang="ts">
import { onMounted } from 'vue'

import AppLayout from './layouts/AppLayout.vue'
import { useAppStore } from './stores/app'
import { useRecoveryStore } from './stores/recovery'

const appStore = useAppStore()
const recoveryStore = useRecoveryStore()

onMounted(() => {
  void appStore.initialize()
  void recoveryStore.refreshOverview()
})
</script>

<template>
  <AppLayout />
</template>
