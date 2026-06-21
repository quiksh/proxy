export const GITHUB_URL = "https://github.com/quiksh/proxy";
export const GITHUB_QUICKSTART_URL =
  "https://github.com/quiksh/proxy#five-minute-quickstart";
export const GITHUB_DOCS_URL = "https://github.com/quiksh/proxy/tree/main/docs";
export const GITHUB_EXAMPLES_URL =
  "https://github.com/quiksh/proxy/tree/main/examples";
export const GITHUB_NATS_EXAMPLES_URL =
  "https://github.com/quiksh/proxy/tree/main/examples/nats";
export const GITHUB_REGISTER_URL =
  "https://github.com/quiksh/proxy/tree/main/quik-register";
export const GHCR_IMAGE = "ghcr.io/quiksh/proxy";

// Page-level nav only. The on-page anchor links (Features, Admin API) were
// dropped - they only worked on the landing page and broke from sub-pages.
export const NAV_LINKS = [
  { label: "Egress", href: "/egress" },
  { label: "Service registration", href: "/service-registration" },
  { label: "Homelab", href: "/homelab" },
  // Canonical docs, rendered by Starlight from the repo's docs/*.md.
  { label: "Docs", href: "/docs" },
];
