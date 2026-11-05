import type { ManifestChangeKind, ManifestChanges } from '@/types/commands'

const KIND_LABELS: Record<ManifestChangeKind, string> = {
  dependencies: 'Dependencies',
  client_scripts: 'Client scripts',
  server_scripts: 'Server scripts',
  shared_scripts: 'Shared scripts',
  files: 'Files',
  ui_pages: 'UI pages',
  escrow_ignore: 'Escrow-ignored files',
}

export interface PresentedManifestChanges {
  fx: string | undefined
  groups: Array<{ kind: ManifestChangeKind; label: string; added: string[]; removed: string[] }>
  omittedCount: number
  /** The disclosure's own label, counting what it holds. */
  label: string
}

/**
 * What an update's manifest declares differently, ready to draw.
 *
 * Nothing here is acted on: the manifest is only read. Absent when there is nothing to say, so a
 * screen can leave the section out instead of showing an empty one.
 */
export function presentManifestChanges(
  changes: ManifestChanges | undefined,
): PresentedManifestChanges | undefined {
  if (changes === undefined) return undefined
  const fx = changes.fxVersion
  if (fx === undefined && changes.groups.length === 0) return undefined
  const count = changes.groups.length + (fx === undefined ? 0 : 1)
  return {
    fx:
      fx === undefined
        ? undefined
        : `${fx.installed ?? 'not declared'} → ${fx.incoming ?? 'not declared'}`,
    groups: changes.groups.map((group) => ({ ...group, label: KIND_LABELS[group.kind] })),
    omittedCount: changes.omittedCount,
    label: `Manifest changes · ${count} ${count === 1 ? 'declaration' : 'declarations'}`,
  }
}
