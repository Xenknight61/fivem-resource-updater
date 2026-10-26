import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

const sourceRoot = join(process.cwd(), 'src')

function stylesheets(): string[] {
  const found: string[] = []
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory)) {
      const path = join(directory, entry)
      if (statSync(path).isDirectory()) {
        walk(path)
        continue
      }
      if (/\.(vue|css)$/.test(entry) && !/\.test\./.test(entry)) found.push(path)
    }
  }
  walk(sourceRoot)
  return found
}

function styleText(path: string): string {
  const text = readFileSync(path, 'utf8')
  if (path.endsWith('.css')) return text
  return [...text.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map((match) => match[1]).join('\n')
}

describe('the design tokens', () => {
  /**
   * A custom property that was never defined does not fail: it falls back, silently, to whatever
   * the second argument says — or to nothing. That is how `--ok` came to render a second green
   * the palette does not contain, and `--rule` a divider that was not the border colour. The
   * damage is that it looks almost right, so nobody sees it.
   */
  it('are all defined somewhere before they are used', () => {
    const files = stylesheets()
    const defined = new Set<string>()
    for (const file of files) {
      for (const match of styleText(file).matchAll(/^\s*(--[a-z0-9-]+)\s*:/gm)) {
        const name = match[1]
        if (name !== undefined) defined.add(name)
      }
    }

    const undefinedUses: string[] = []
    for (const file of files) {
      styleText(file)
        .split('\n')
        .forEach((line, index) => {
          for (const match of line.matchAll(/var\((--[a-z0-9-]+)/g)) {
            const name = match[1]
            if (name !== undefined && !defined.has(name)) {
              undefinedUses.push(`${name} at ${file.slice(sourceRoot.length + 1)}:${index + 1}`)
            }
          }
        })
    }

    expect(undefinedUses).toEqual([])
  })

  /**
   * A control's edge has to be visible to the same standard everywhere, so the colour that draws
   * it is checked here rather than trusted to stay put. WCAG 1.4.11 asks 3:1 against whatever
   * the control sits on; `--border`, which separates regions rather than identifying controls,
   * is deliberately quieter and is not held to it.
   */
  it('draw a control edge that clears the non-text contrast standard', () => {
    const tokens = readFileSync(join(sourceRoot, 'styles', 'tokens.css'), 'utf8')
    const value = (name: string) => {
      const hex = tokens.match(new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`))?.[1]
      if (hex === undefined) throw new Error(`${name} is not defined as a hex colour`)
      return hex
    }
    const weights = [0.2126, 0.7152, 0.0722]
    const luminance = (hex: string) =>
      [1, 3, 5].reduce((total, start, channel) => {
        const value = parseInt(hex.slice(start, start + 2), 16) / 255
        const linear = value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4
        return total + linear * (weights[channel] ?? 0)
      }, 0)
    const contrast = (first: string, second: string) => {
      const one = luminance(first)
      const other = luminance(second)
      return (Math.max(one, other) + 0.05) / (Math.min(one, other) + 0.05)
    }

    const edge = value('--control-border')
    for (const surface of ['--background', '--surface', '--surface-raised']) {
      expect(contrast(edge, value(surface))).toBeGreaterThanOrEqual(3)
    }
  })
})
