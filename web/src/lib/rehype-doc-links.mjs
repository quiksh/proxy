// Rewrite the repo docs' GitHub-relative cross-links to site routes.
//
// The canonical docs in `../docs/*.md` link to each other with plain relative
// markdown paths (`[Hardening](hardening.md)`, `(admin-api.md#config-reload)`)
// so they render correctly on GitHub. Because Starlight sources them from
// outside its standard content dir, Astro's built-in link resolver can't remap
// those `.md` targets — so we do it here. Every doc lives flat in `docs/` and
// renders at `/docs/<name>/`, which makes the mapping a one-liner.
//
// Links with a path separator (e.g. `../README.md`, `../examples/nats`) or a
// non-`.md` target are left untouched — they point outside the docs set and are
// GitHub-oriented by design.
const MD_LINK = /^(?:\.\/)?([\w-]+)\.md(#.*)?$/;

export function rehypeDocLinks() {
  const walk = (node) => {
    if (
      node.type === "element" &&
      node.tagName === "a" &&
      typeof node.properties?.href === "string"
    ) {
      const m = node.properties.href.match(MD_LINK);
      if (m) {
        const anchor = m[2] ?? "";
        node.properties.href = `/docs/${m[1]}/${anchor}`;
      }
    }
    if (Array.isArray(node.children)) {
      for (const child of node.children) walk(child);
    }
  };
  return (tree) => walk(tree);
}
