<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { goto } from "$app/navigation";
  import { open } from "@tauri-apps/plugin-dialog";

  type DevSettings = {
    enabled: boolean;
    binariesSource: "main" | "custom";
    osSource: "main" | "custom";
    binariesRepo: string;
    osRepo: string;
    customWicPath: string;
    key1Name: string;
    key1User: string;
    key2Name: string;
    key2User: string;
    githubToken: string;
    manifestVersionOverride: string;
    maskUserPathsWithDemo: boolean;
  };

  const STORAGE_KEY = "secluso-dev-settings";
  const backIcon = "/deploy-assets/settings-back-latest.svg";
  const gearGhost = "/deploy-assets/settings-gear-ghost-latest.svg";
  const devOptionsIcon = "/deploy-assets/settings-dev-options-latest.svg";

  const defaultSettings: DevSettings = {
    enabled: false,
    binariesSource: "main",
    osSource: "main",
    binariesRepo: "",
    osRepo: "",
    customWicPath: "",
    key1Name: "",
    key1User: "",
    key2Name: "",
    key2User: "",
    githubToken: "",
    manifestVersionOverride: "",
    maskUserPathsWithDemo: false
  };

  let devSettings: DevSettings = { ...defaultSettings };
  let saveSuccess = false;
  let saveResetTimer: ReturnType<typeof setTimeout> | null = null;

  onMount(() => {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw) as Partial<DevSettings>;
      devSettings = { ...defaultSettings, ...parsed };
    } catch {
      devSettings = { ...defaultSettings };
    }
  });

  function saveSettings() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(devSettings));
    saveSuccess = true;
    if (saveResetTimer) clearTimeout(saveResetTimer);
    saveResetTimer = setTimeout(() => {
      saveSuccess = false;
      saveResetTimer = null;
    }, 1600);
  }

  function goBack() {
    goto("/");
  }

  async function pickCustomWic() {
    const path = await open({
      title: "Choose custom WIC image",
      multiple: false,
      directory: false,
      filters: [{ name: "WIC image", extensions: ["wic"] }]
    });
    if (typeof path === "string" && path.length) devSettings.customWicPath = path;
    if (Array.isArray(path) && path.length) devSettings.customWicPath = path[0];
  }

  onDestroy(() => {
    if (saveResetTimer) clearTimeout(saveResetTimer);
  });
</script>

<main class="page">
  <div class="page-backdrop"></div>
  <section class="content">
    <a class="back-link" href="/" on:click|preventDefault={goBack}>
      <img src={backIcon} alt="" />
      <span>Back</span>
    </a>

    <div class="hero">
      <h1>Settings</h1>
      <img class="gear-ghost" src={gearGhost} alt="" />
    </div>

    <section class="mode-card">
      <label class="switch-row">
        <span class="switch">
          <input type="checkbox" bind:checked={devSettings.enabled} />
          <span class="switch-track"></span>
        </span>
        <span class="switch-copy">
          <strong>Developer mode</strong>
          <small>Extra options for testing and staging.</small>
        </span>
      </label>
    </section>

    {#if devSettings.enabled}
      <section class="developer-card">
        <div class="developer-heading">
          <img src={devOptionsIcon} alt="" />
          <span>Developer Options</span>
        </div>

        <section class="option-card">
          <div class="option-header">
            <h2>Demo</h2>
            <span class="badge">OPTIONAL</span>
          </div>
          <label class="switch-row compact">
            <span class="switch">
              <input type="checkbox" bind:checked={devSettings.maskUserPathsWithDemo} />
              <span class="switch-track"></span>
            </span>
            <span class="option-label">Hide username in paths with "demo"</span>
          </label>
          <p>Masks displayed macOS home paths as <code>/Users/demo</code> in fields, errors, and copied logs.</p>
        </section>

        <section class="option-card binaries-card">
          <div class="option-header">
            <h2>Binaries</h2>
            <span class="badge">OPTIONAL</span>
          </div>

          <label class="radio-row">
            <input type="radio" name="binaries" value="main" bind:group={devSettings.binariesSource} />
            <span>Use main release binaries</span>
          </label>

          <label class="radio-row">
            <input type="radio" name="binaries" value="custom" bind:group={devSettings.binariesSource} />
            <span>Use another repo</span>
          </label>

          {#if devSettings.binariesSource === "custom"}
            <div class="custom-fields">
              <label class="field">
                <span>Repo</span>
                <input
                  bind:value={devSettings.binariesRepo}
                  placeholder="secluso/secluso"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                />
              </label>
              <label class="field">
                <span>Key 1 name</span>
                <input
                  bind:value={devSettings.key1Name}
                  placeholder="release-key-1"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                />
              </label>
              <label class="field">
                <span>Key 1 GitHub username</span>
                <input
                  bind:value={devSettings.key1User}
                  placeholder="username1"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                />
              </label>
              <label class="field">
                <span>Key 2 name</span>
                <input
                  bind:value={devSettings.key2Name}
                  placeholder="release-key-2"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                />
              </label>
              <label class="field">
                <span>Key 2 GitHub username</span>
                <input
                  bind:value={devSettings.key2User}
                  placeholder="username2"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                />
              </label>
            </div>
          {/if}
        </section>


        <section class="option-card binaries-card">
          <div class="option-header">
            <h2>OS</h2>
            <span class="badge">OPTIONAL</span>
          </div>

          <label class="radio-row">
            <input type="radio" name="os" value="main" bind:group={devSettings.osSource} />
            <span>Use main release OS</span>
          </label>

          <label class="radio-row">
            <input type="radio" name="os" value="custom" bind:group={devSettings.osSource} />
            <span>Use another repo</span>
          </label>

          {#if devSettings.osSource === "custom"}
            <div class="custom-fields">
              <label class="field">
                <span>Repo</span>
                <input
                  bind:value={devSettings.osRepo}
                  placeholder="secluso/os"
                  autocorrect="off"
                  autocapitalize="off"
                  spellcheck="false"
                />
              </label>
            </div>
          {/if}
        </section>

        <section class="option-card custom-wic-card">
          <div class="option-header">
            <h2>Custom WIC Image</h2>
            <span class="badge">OPTIONAL</span>
          </div>

          <div class="path-picker">
            <label class="field">
              <span>WIC path</span>
              <input
                bind:value={devSettings.customWicPath}
                placeholder="/path/to/secluso-pi-image.wic"
                autocorrect="off"
                autocapitalize="off"
                spellcheck="false"
              />
            </label>
            <button class="picker-button" on:click={pickCustomWic}>Choose</button>
          </div>
          <p>When set, image preparation uses this custom WIC as the base image instead of downloading the released Secluso OS WIC.</p>
        </section>

        <section class="option-card token-card">
          <div class="option-header">
            <h2>GitHub Token</h2>
            <span class="badge">OPTIONAL</span>
          </div>

          <label class="field">
            <span>Token</span>
            <input
              type="password"
              bind:value={devSettings.githubToken}
              placeholder="ghp_..."
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
            />
          </label>
          <p>Used for GitHub API requests to avoid rate limits.</p>
        </section>

        <section class="option-card token-card">
          <div class="option-header">
            <h2>Manifest Version Override</h2>
            <span class="badge">OPTIONAL</span>
          </div>

          <label class="field">
            <span>Version</span>
            <input
              bind:value={devSettings.manifestVersionOverride}
              placeholder="1.0.0"
              autocorrect="off"
              autocapitalize="off"
              spellcheck="false"
            />
          </label>
          <p>Overrides the version sent in the post-install server health check.</p>
        </section>
      </section>
    {/if}

    <div class="save-row">
      <button class:success={saveSuccess} class="save-button" on:click={saveSettings}>
        {saveSuccess ? "Saved" : "Save"}
      </button>
      {#if saveSuccess}
        <span class="save-status" aria-live="polite">Settings saved</span>
      {/if}
    </div>
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    background: #030303;
    color: #fff;
    font-family: Inter, "Segoe UI", sans-serif;
  }

  :global(*) {
    box-sizing: border-box;
  }

  .page {
    min-height: 100vh;
    background: #030303;
    position: relative;
    overflow-x: hidden;
    padding-bottom: 72px;
  }

  .page-backdrop {
    position: fixed;
    inset: 0;
    pointer-events: none;
    background:
      radial-gradient(420px 220px at 50% 0, rgba(43, 127, 255, 0.1), transparent 68%),
      linear-gradient(180deg, rgba(3, 3, 3, 0.98), #030303 42%);
    opacity: 0.45;
  }

  .content {
    position: relative;
    width: min(calc(100% - 48px), 528px);
    margin: 0 auto;
    padding-top: 44px;
    z-index: 1;
  }

  .back-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 28px;
    color: rgba(255, 255, 255, 0.4);
    font-size: 13px;
    line-height: 19.5px;
    text-decoration: none;
  }

  .back-link img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .hero {
    position: relative;
    min-height: 68px;
    margin-bottom: 32px;
  }

  h1 {
    margin: 0;
    font-size: 30px;
    line-height: 36px;
    letter-spacing: -0.75px;
    font-weight: 600;
  }

  .gear-ghost {
    position: absolute;
    right: -16px;
    top: -16px;
    width: 128px;
    height: 128px;
    display: block;
    pointer-events: none;
  }

  .mode-card,
  .developer-card,
  .option-card {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.05);
  }

  .mode-card,
  .developer-card {
    border-radius: 20px;
  }

  .mode-card {
    padding: 20px;
  }

  .switch-row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    cursor: pointer;
  }

  .switch-row.compact {
    align-items: center;
    gap: 12px;
  }

  .switch {
    position: relative;
    flex: 0 0 auto;
    width: 32px;
    height: 18.4px;
    margin-top: 2px;
  }

  .switch input {
    position: absolute;
    inset: 0;
    opacity: 0;
    cursor: pointer;
    margin: 0;
  }

  .switch-track {
    position: absolute;
    inset: 0;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.05);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
    transition: background 0.16s ease;
  }

  .switch-track::after {
    content: "";
    position: absolute;
    top: 1.2px;
    left: 0;
    width: 16px;
    height: 16px;
    border-radius: 999px;
    background: #030303;
    transition: left 0.16s ease;
  }

  .switch input:checked + .switch-track {
    background: #2b7fff;
  }

  .switch input:checked + .switch-track::after {
    left: 14px;
  }

  .switch-copy {
    display: grid;
    gap: 4px;
  }

  .switch-copy strong {
    font-size: 15px;
    line-height: 22.5px;
    font-weight: 500;
    color: #fff;
  }

  .switch-copy small {
    font-size: 13px;
    line-height: 19.5px;
    color: rgba(255, 255, 255, 0.4);
  }

  .developer-card {
    margin-top: 32px;
    padding: 20px;
  }

  .developer-heading {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-bottom: 17px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    margin-bottom: 19px;
  }

  .developer-heading img {
    width: 16px;
    height: 16px;
    display: block;
  }

  .developer-heading span {
    font-size: 13px;
    line-height: 19.5px;
    letter-spacing: 0.65px;
    text-transform: uppercase;
    color: rgba(255, 255, 255, 0.6);
    font-weight: 500;
  }

  .option-card {
    border-radius: 16px;
    padding: 16px;
  }

  .option-card + .option-card {
    margin-top: 16px;
  }

  .option-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 18px;
  }

  .option-header h2 {
    margin: 0;
    font-size: 15px;
    line-height: 22.5px;
    font-weight: 600;
  }

  .badge {
    display: inline-flex;
    align-items: center;
    height: 20.5px;
    padding: 0 8px;
    border-radius: 999px;
    background: rgba(43, 127, 255, 0.1);
    color: #51a2ff;
    font-size: 11px;
    line-height: 16.5px;
    font-weight: 500;
  }

  .option-label {
    font-size: 14px;
    line-height: 21px;
    color: #fff;
  }

  .option-card p {
    margin: 10px 0 0;
    font-size: 13px;
    line-height: 19.5px;
    color: rgba(255, 255, 255, 0.4);
  }

  .token-card {
    padding-bottom: 18px;
  }

  .field {
    display: grid;
    gap: 6px;
    margin-top: 18px;
  }

  .field span {
    font-size: 13px;
    line-height: 19.5px;
    color: rgba(255, 255, 255, 0.5);
  }

  .field input {
    width: 100%;
    height: 24px;
    border: 0;
    outline: 0;
    padding: 0;
    background: transparent;
    color: #fafafa;
    font-size: 16px;
    line-height: 24px;
    font-family: inherit;
  }

  .field input::placeholder {
    color: rgba(250, 250, 250, 0.5);
  }

  .binaries-card {
    padding-bottom: 18px;
  }

  .radio-row {
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 21px;
    color: #fff;
    font-size: 14px;
    line-height: 21px;
    cursor: pointer;
  }

  .radio-row + .radio-row {
    margin-top: 8px;
  }

  .radio-row input {
    appearance: none;
    -webkit-appearance: none;
    width: 16px;
    height: 16px;
    margin: 0;
    border-radius: 999px;
    border: 1px solid #767676;
    background: #fff;
    position: relative;
    flex: 0 0 auto;
  }

  .radio-row input:checked {
    border-color: #0075ff;
  }

  .radio-row input:checked::after {
    content: "";
    position: absolute;
    inset: 2.2px;
    border-radius: 999px;
    background: #0075ff;
  }

  .custom-fields {
    margin-top: 16px;
    display: grid;
    gap: 12px;
  }

  .custom-fields .field {
    margin-top: 0;
  }

  .custom-wic-card {
    padding-bottom: 18px;
  }

  .path-picker {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: end;
    gap: 12px;
  }

  .path-picker .field {
    margin-top: 0;
  }

  .picker-button {
    min-width: 82px;
    height: 36px;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    background: rgba(255, 255, 255, 0.04);
    color: #fff;
    font-size: 13px;
    line-height: 19.5px;
    font-family: inherit;
    cursor: pointer;
  }

  .save-row {
    margin-top: 32px;
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .save-button {
    width: 80.4px;
    height: 45px;
    border: 0;
    border-radius: 20px;
    background: #3b82f6;
    color: #fff;
    font-size: 14px;
    line-height: 21px;
    font-weight: 500;
    font-family: inherit;
    cursor: pointer;
    transition: background-color 0.16s ease;
  }

  .save-button.success {
    background: #00bc7d;
  }

  .save-status {
    color: rgba(0, 212, 146, 0.9);
    font-size: 12px;
    line-height: 18px;
  }

  @media (max-width: 640px) {
    .content {
      width: calc(100% - 32px);
      padding-top: 44px;
    }

    .gear-ghost {
      right: -22px;
      top: -6px;
      width: 112px;
      height: 112px;
    }

    .developer-card {
      padding: 16px;
    }

    .mode-card {
      padding: 16px;
    }

    .option-card {
      padding: 14px;
    }

    .path-picker {
      grid-template-columns: 1fr;
      align-items: stretch;
    }

    .picker-button {
      width: 100%;
    }
  }
</style>
