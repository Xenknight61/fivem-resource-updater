import { describe, expect, it } from 'vitest'

import { decodeUpdatePlanGetChangeDiffResponse } from './decoders'

/**
 * The diff response is the one place file content crosses the IPC boundary, so the decoder is
 * the frontend's half of that boundary: anything past a bound, or content attached to a
 * response that claims no content is available, is rejected rather than rendered.
 */
describe('decodeUpdatePlanGetChangeDiffResponse', () => {
  const line = { origin: 'installed', text: "Config.Locale = 'tr'", truncated: false }

  it('accepts a bounded available response', () => {
    const decoded = decodeUpdatePlanGetChangeDiffResponse({
      availability: 'available',
      lines: [line],
      truncated: false,
    })
    expect(decoded.lines).toHaveLength(1)
    expect(decoded.lines[0]?.origin).toBe('installed')
  })

  it('accepts an empty unavailable response', () => {
    for (const availability of ['protected_content', 'not_merged']) {
      const decoded = decodeUpdatePlanGetChangeDiffResponse({
        availability,
        lines: [],
        truncated: false,
      })
      expect(decoded.lines).toHaveLength(0)
    }
  })

  it('rejects content attached to a response that claims none is available', () => {
    // Protected content must never render, so a response that says "protected" and still
    // carries lines is treated as malformed rather than displayed.
    for (const availability of ['protected_content', 'not_merged']) {
      expect(() =>
        decodeUpdatePlanGetChangeDiffResponse({ availability, lines: [line], truncated: false }),
      ).toThrow()
    }
  })

  it('rejects unknown availabilities and origins', () => {
    expect(() =>
      decodeUpdatePlanGetChangeDiffResponse({ availability: 'sure', lines: [], truncated: false }),
    ).toThrow()
    expect(() =>
      decodeUpdatePlanGetChangeDiffResponse({
        availability: 'available',
        lines: [{ ...line, origin: 'vendor' }],
        truncated: false,
      }),
    ).toThrow()
  })

  it('rejects anything past the backend bounds', () => {
    expect(() =>
      decodeUpdatePlanGetChangeDiffResponse({
        availability: 'available',
        lines: Array.from({ length: 401 }, () => line),
        truncated: true,
      }),
    ).toThrow()
    expect(() =>
      decodeUpdatePlanGetChangeDiffResponse({
        availability: 'available',
        lines: [{ ...line, text: 'x'.repeat(241) }],
        truncated: false,
      }),
    ).toThrow()
  })

  it('rejects malformed shapes', () => {
    for (const value of [undefined, null, 'diff', { availability: 'available' }]) {
      expect(() => decodeUpdatePlanGetChangeDiffResponse(value)).toThrow()
    }
  })
})
