// SPDX-License-Identifier: MPL-2.0
// This file is part of the LocalPass desktop GUI. See ../../LICENSE.

// Turn GitHub's generated release notes into a few plain blocks for the
// in-app changelog. Deliberately tiny and text-only: no HTML is ever produced
// (Svelte escapes the strings), links are dropped rather than rendered (the
// webview has nowhere safe to navigate), and only the shapes GitHub's
// "generate notes" emits are understood: headings, bullets, paragraphs.
//
//   ## What's Changed
//   * feat(gui): redesigned shell by @someone in https://github.com/o/r/pull/42
//
//   **Full Changelog**: https://github.com/o/r/compare/v0.1.3...v0.1.4

export type NoteBlock =
  | { kind: "heading"; text: string }
  | { kind: "item"; text: string }
  | { kind: "text"; text: string };

/** Remove GitHub's attribution tail and inline Markdown emphasis/links. */
export function cleanLine(line: string): string {
  return (
    line
      // " by @user in https://github.com/…/pull/42"
      .replace(/\s+by\s+@[\w-]+(\[bot\])?\s+in\s+https?:\/\/\S+$/i, "")
      // [text](url) -> text
      .replace(/\[([^\]]+)\]\((?:[^)]+)\)/g, "$1")
      // bare URLs
      .replace(/https?:\/\/\S+/g, "")
      // **bold**, __bold__, `code`
      .replace(/\*\*([^*]+)\*\*/g, "$1")
      .replace(/__([^_]+)__/g, "$1")
      .replace(/`([^`]+)`/g, "$1")
      .replace(/\s{2,}/g, " ")
      .trim()
  );
}

export function parseReleaseNotes(md: string): NoteBlock[] {
  const blocks: NoteBlock[] = [];
  for (const raw of md.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    // GitHub's footer and comment markers carry no change information.
    if (/^\*\*full changelog\*\*/i.test(line) || line.startsWith("<!--")) continue;
    const heading = line.match(/^#{1,6}\s+(.*)$/);
    if (heading) {
      const text = cleanLine(heading[1]);
      if (text) blocks.push({ kind: "heading", text });
      continue;
    }
    const bullet = line.match(/^[*-]\s+(.*)$/);
    if (bullet) {
      const text = cleanLine(bullet[1]);
      if (text) blocks.push({ kind: "item", text });
      continue;
    }
    const text = cleanLine(line);
    if (text) blocks.push({ kind: "text", text });
  }
  return blocks;
}
