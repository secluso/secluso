<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import packageInfo from "../../../package.json";
  import { getDeployVersionStatus, openExternalUrl } from "$lib/api";

  type VersionPillState = "checking" | "latest" | "outdated" | "unknown";
  type VersionStatusUpdate = {
    state: VersionPillState;
    currentVersion: string;
    latestVersion: string | null;
  };

  export let version = `v${packageInfo.version}`;
  export let settingsHref = "/settings";
  export let onVersionStatusChange: (status: VersionStatusUpdate) => void = () => {};

  let versionLabel = version;
  let latestVersion: string | null = null;
  let pillState: VersionPillState = "checking";

  $: versionLabel = versionLabel || version;
  $: showVersionPill = pillState !== "unknown";
  $: pillText =
    pillState === "outdated"
      ? "Outdated"
      : pillState === "checking"
        ? "Checking"
        : "Latest version";
  $: pillTitle =
    pillState === "outdated" && latestVersion
      ? `Current ${versionLabel}; latest ${latestVersion}`
      : pillState === "latest" && latestVersion
        ? `Current ${versionLabel}; latest ${latestVersion}`
        : "Checking latest deploy app version";

  onMount(async () => {
    notifyVersionStatusChange();
    try {
      const status = await getDeployVersionStatus();
      versionLabel = status.currentVersion;
      latestVersion = status.latestVersion;
      pillState = status.outdated ? "outdated" : "latest";
      notifyVersionStatusChange();
    } catch {
      pillState = "unknown";
      notifyVersionStatusChange();
    }
  });

  function notifyVersionStatusChange() {
    onVersionStatusChange({
      state: pillState,
      currentVersion: versionLabel,
      latestVersion
    });
  }

  async function openExternal(url: string) {
    try {
      await openExternalUrl(url);
    } catch {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }
</script>

<header class="shared-header">
  <div class="shared-header__inner">
    <div class="shared-header__brand">
      <img class="shared-header__mark" src="/deploy-assets/header-mark.jpeg" alt="" />
      <span class="shared-header__name">Secluso</span>
      <small class="shared-header__version">{versionLabel}</small>
      {#if showVersionPill}
        <span
          class={`shared-header__pill shared-header__pill--${pillState}`}
          title={pillTitle}
          aria-live="polite"
        >
          <i></i>{pillText}
        </span>
      {/if}
    </div>

    <div class="shared-header__actions">
      <a
        class="shared-header__store shared-header__store--ios"
        href="https://apps.apple.com/us/app/secluso/id6756543429"
        on:click|preventDefault={() => openExternal("https://apps.apple.com/us/app/secluso/id6756543429")}
      >
        <img src="/deploy-assets/header-ios-latest.svg" alt="" />
        <span>iOS</span>
      </a>

      <a
        class="shared-header__store shared-header__store--android"
        href="https://play.google.com/store/apps/details?id=com.secluso.mobile"
        on:click|preventDefault={() => openExternal("https://play.google.com/store/apps/details?id=com.secluso.mobile")}
      >
        <img src="/deploy-assets/header-android-latest.svg" alt="" />
        <span>Android</span>
      </a>

      <a class="shared-header__settings" href={settingsHref} aria-label="Settings">
        <img src="/deploy-assets/header-settings-latest.svg" alt="" />
      </a>
    </div>
  </div>
</header>

<style>
  .shared-header {
    height: 57px;
    position: sticky;
    top: 0;
    z-index: 30;
    backdrop-filter: blur(12px);
    background: rgba(3, 3, 3, 0.9);
    border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  }

  .shared-header__inner {
    width: min(616px, calc(100% - 48px));
    height: 100%;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .shared-header__brand {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 0;
  }

  .shared-header__mark {
    width: 28px;
    height: 28px;
    border-radius: 16px;
    box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.06);
    display: block;
    flex: 0 0 auto;
  }

  .shared-header__name {
    color: #fff;
    font-size: 14px;
    font-weight: 500;
    line-height: 21px;
  }

  .shared-header__version {
    color: rgba(255, 255, 255, 0.25);
    font-size: 11px;
    font-weight: 500;
    line-height: 16.5px;
  }

  .shared-header__pill {
    height: 25px;
    padding: 0 8px;
    border-radius: 999px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(0, 188, 125, 0.08);
    border: 1px solid rgba(0, 188, 125, 0.1);
    color: rgba(0, 212, 146, 0.9);
    font-size: 10px;
    font-weight: 500;
    line-height: 15px;
    white-space: nowrap;
  }

  .shared-header__pill--checking {
    background: rgba(255, 255, 255, 0.05);
    border-color: rgba(255, 255, 255, 0.08);
    color: rgba(255, 255, 255, 0.6);
  }

  .shared-header__pill--outdated {
    background: rgba(245, 158, 11, 0.12);
    border-color: rgba(245, 158, 11, 0.24);
    color: #fbbf24;
  }

  .shared-header__pill i {
    width: 6px;
    height: 6px;
    border-radius: 999px;
    background: #00d492;
    flex: 0 0 auto;
  }

  .shared-header__pill--checking i {
    background: rgba(255, 255, 255, 0.4);
  }

  .shared-header__pill--outdated i {
    background: #f59e0b;
  }

  .shared-header__actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 0 0 auto;
  }

  .shared-header__store {
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    border-radius: 16px;
    font-size: 10px;
    font-weight: 600;
    line-height: 15px;
    box-sizing: border-box;
  }

  .shared-header__store img {
    display: block;
    flex: 0 0 auto;
  }

  .shared-header__store--ios {
    width: 56.8px;
    height: 27px;
    background: #fff;
    color: #000;
  }

  .shared-header__store--ios img {
    width: 14px;
    height: 14px;
  }

  .shared-header__store--android {
    width: 78.34px;
    height: 29px;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: rgba(255, 255, 255, 0.8);
  }

  .shared-header__store--android img {
    width: 12px;
    height: 12px;
  }

  .shared-header__settings {
    width: 16px;
    height: 16px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 auto;
  }

  .shared-header__settings img {
    width: 16px;
    height: 16px;
    display: block;
  }

  @media (max-width: 720px) {
    .shared-header__inner {
      width: calc(100% - 32px);
    }

    .shared-header__brand {
      gap: 8px;
    }

    .shared-header__pill {
      display: none;
    }
  }
</style>
