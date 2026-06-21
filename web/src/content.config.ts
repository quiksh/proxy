import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { docsSchema } from "@astrojs/starlight/schema";

// Starlight's docs are sourced directly from the repo's `docs/*.md` (one
// directory up, since this site lives in the monorepo at `proxy/web/`). That
// markdown is the single source of truth — editing a doc updates the site, no
// copy/sync. Entry ids are prefixed with `docs/` so the canonical docs render
// under `/docs/<name>` and don't collide with the custom marketing pages at the
// site root (e.g. `/homelab`, `/service-registration`).
export const collections = {
  docs: defineCollection({
    loader: glob({
      pattern: "**/*.md",
      base: "../docs",
      generateId: ({ entry }) => `docs/${entry.replace(/\.md$/, "")}`,
    }),
    schema: docsSchema(),
  }),
};
