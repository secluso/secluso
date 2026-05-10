// SPDX-License-Identifier: GPL-3.0-or-later
// Tauri doesn't have a Node.js server to do proper SSR
// so we will use adapter-static to prerender the app (SSG)
// See: https://v2.tauri.app/start/frontend/sveltekit/ for more info
import adapter from "@sveltejs/adapter-static";
import { readFileSync } from "node:fs";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

function readReleaseVersion() {
  const releaseVersion = readFileSync(
    new URL("./release-version.txt", import.meta.url),
    "utf8",
  ).trim();
  if (!releaseVersion) {
    throw new Error("deploy/release-version.txt must contain a release version");
  }
  return releaseVersion;
}

// SvelteKit's default version hash is build-time dependent.
// We pin it to a manually bumped release value so unrelated commits (e.g. README changes) do not rename assets.
const deterministicVersion = readReleaseVersion();

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    version: {
      name: deterministicVersion,
    },
  },
};

export default config;
