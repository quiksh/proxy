// @ts-check
import { defineConfig } from "astro/config";
import icon from "astro-icon";
import starlight from "@astrojs/starlight";
import { rehypeDocLinks } from "./src/lib/rehype-doc-links.mjs";

const GITHUB_URL = "https://github.com/quiksh/proxy";

// https://astro.build
export default defineConfig({
  site: "https://quik.sh",
  // Rewrite the repo docs' relative `*.md` cross-links to `/docs/*` routes.
  markdown: {
    rehypePlugins: [rehypeDocLinks],
  },
  // The custom marketing pages own the site root (`/`, `/homelab`, ...).
  // Starlight renders the canonical docs under `/docs/*`; send `/docs` to a
  // sensible entry point.
  redirects: {
    "/docs": "/docs/ha-reverse-proxy",
  },
  integrations: [
    icon(),
    starlight({
      title: "quik docs",
      description:
        "Reference and guides for quik — a small, fast reverse proxy in Rust.",
      customCss: ["./src/styles/starlight.css"],
      social: [{ icon: "github", label: "GitHub", href: GITHUB_URL }],
      editLink: {
        // Each doc's source path is recorded relative to this project
        // (`../docs/<name>.md`, since the site lives at `proxy/web/`). Starlight
        // resolves that against this base as a URL, so the leading `../` pops a
        // segment — anchoring the base at `.../edit/main/web/` makes
        // `../docs/<name>.md` resolve back to `.../edit/main/docs/<name>.md`.
        baseUrl: `${GITHUB_URL}/edit/main/web/`,
      },
      // Map sidebar entries to the `docs/`-prefixed collection slugs.
      sidebar: [
        {
          label: "Guides",
          items: [
            { slug: "docs/ha-reverse-proxy" },
            { slug: "docs/homelab" },
            { slug: "docs/forward-proxy" },
            { slug: "docs/hardening" },
            { slug: "docs/graceful-shutdown" },
            { slug: "docs/service-registration" },
          ],
        },
        {
          label: "Reference",
          items: [{ slug: "docs/admin-api" }, { slug: "docs/config-reference" }],
        },
      ],
    }),
  ],
});
