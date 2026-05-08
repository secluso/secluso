<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount, tick } from "svelte";
  import { goto } from "$app/navigation";
  import AppHeader from "$lib/components/AppHeader.svelte";

  type VersionGateState = "checking" | "latest" | "outdated" | "unknown";
  type VersionStatusUpdate = {
    state: VersionGateState;
    currentVersion: string;
    latestVersion: string | null;
  };

  const FIRST_TIME_KEY = "secluso-first-time";
  const homeBackdropFill = "/deploy-assets/home-backdrop-fill-latest.svg";
  const homeMark = "/deploy-assets/home-logo.jpeg";
  const homeSignal = "/deploy-assets/home-signal-latest.svg";
  const homeChipTime = "/deploy-assets/home-chip-time-latest.svg";
  const homeChipE2ee = "/deploy-assets/home-chip-e2ee-latest.svg";
  const homeFirstTime = "/deploy-assets/home-first-time-latest.svg";
  const homeStepOneBg = "/deploy-assets/home-step-1-bg-latest.svg";
  const homeStepTwoBg = "/deploy-assets/home-step-2-bg-latest.svg";
  const homeStepArrow = "/deploy-assets/home-step-arrow-latest.svg";
  const homeStepOneIcon = "/deploy-assets/home-step-1-icon-latest.svg";
  const homeStepTwoIcon = "/deploy-assets/home-step-2-icon-latest.svg";

  let firstTimeOn = false;
  let helpPanel: HTMLElement | null = null;
  let versionGate: VersionStatusUpdate = {
    state: "checking",
    currentVersion: "v1.0.0",
    latestVersion: null
  };
  let pendingRoute: string | null = null;

  onMount(() => {
    const raw = localStorage.getItem(FIRST_TIME_KEY);
    if (raw === null) {
      firstTimeOn = false;
      return;
    }
    firstTimeOn = raw === "true";
  });

  async function toggleFirstTime() {
    firstTimeOn = !firstTimeOn;
    localStorage.setItem(FIRST_TIME_KEY, String(firstTimeOn));

    if (!firstTimeOn) return;

    await tick();
    helpPanel?.scrollIntoView({ behavior: "smooth", block: "end" });
  }

  function setHelpRef() {
    try {
      sessionStorage.setItem("secluso-help-ref", window.location.pathname);
    } catch {
      // best effort only
    }
  }

  function updateVersionGate(status: VersionStatusUpdate) {
    versionGate = status;
  }

  function openStep(event: MouseEvent, route: string) {
    event.preventDefault();
    if (versionGate.state === "latest") {
      goto(route);
      return;
    }
    pendingRoute = route;
  }

  function closeVersionWarning() {
    pendingRoute = null;
  }

  function continuePastVersionWarning() {
    const route = pendingRoute;
    pendingRoute = null;
    if (route) goto(route);
  }

  $: versionWarningTitle =
    versionGate.state === "outdated" ? "Deploy tool may be outdated" : "Could not confirm latest version";
  $: versionWarningBody =
    versionGate.state === "outdated" && versionGate.latestVersion
      ? `This deploy tool is ${versionGate.currentVersion}. The latest release appears to be ${versionGate.latestVersion}. Please update the deploy tool before continuing, or continue only if you have checked that this version is okay to use.`
      : "The deploy tool has not confirmed whether it is up to date. The network check may still be running or may have failed. Please check the latest Secluso release yourself before continuing.";
  $: if (pendingRoute && versionGate.state === "latest") {
    continuePastVersionWarning();
  }
</script>

<main class="page">
  <div class="page-backdrop"></div>
  <AppHeader onVersionStatusChange={updateVersionGate} />

  <section class="home-frame">
    <div class="hero">
      <div class="hero-outline" aria-hidden="true">
        <img src={homeBackdropFill} alt="" />
      </div>

      <div class="hero-mark-shell">
        <img class="hero-mark" src={homeMark} alt="" />
        <span class="hero-signal"><img src={homeSignal} alt="" /></span>
      </div>

      <h1>Secluso Deploy</h1>

      <div class="hero-meta">
        <span>Private cameras in</span>
        <span class="meta-chip meta-chip--time"><img src={homeChipTime} alt="" />2 min</span>
        <span>with</span>
        <span class="meta-chip meta-chip--e2ee"><img src={homeChipE2ee} alt="" />E2EE</span>
      </div>

      <button class="first-time" type="button" aria-pressed={firstTimeOn} on:click={toggleFirstTime}>
        <img src={homeFirstTime} alt="" />
        <span>First time?</span>
        <span class:enabled={firstTimeOn} class="first-time__switch">
          <i></i>
        </span>
      </button>
    </div>

    <div class="section-label">Setup Steps</div>

    <a class="step-card" href="/image" on:click={(event) => openStep(event, "/image")}>
      <img class="step-card__bg" src={homeStepOneBg} alt="" />
      <span class="step-card__icon step-card__icon--one"><img src={homeStepOneIcon} alt="" /></span>
      <span class="step-card__badge step-card__badge--one">1</span>
      <div class="step-card__copy">
        <div class="step-card__title-row">
          <h2>Raspberry Pi</h2>
          <span>Build image</span>
        </div>
        <p>Generate a Pi OS image and camera pairing QR code.</p>
      </div>
      <span class="step-card__arrow"><img src={homeStepArrow} alt="" /></span>
    </a>

    <a class="step-card" href="/server-ssh" on:click={(event) => openStep(event, "/server-ssh")}>
      <img class="step-card__bg" src={homeStepTwoBg} alt="" />
      <span class="step-card__icon step-card__icon--two"><img src={homeStepTwoIcon} alt="" /></span>
      <span class="step-card__badge step-card__badge--two">2</span>
      <div class="step-card__copy">
        <div class="step-card__title-row">
          <h2>Server</h2>
          <span>Deploy via SSH</span>
        </div>
        <p>Install Secluso on any Linux machine via SSH.</p>
      </div>
      <span class="step-card__arrow"><img src={homeStepArrow} alt="" /></span>
    </a>

    {#if firstTimeOn}
      <section class="help-panel" bind:this={helpPanel}>
        <ol class="quick-steps">
          <li>Install the Secluso app on your phone.</li>
          <li>Build the Raspberry Pi image and keep the camera QR code.</li>
          <li>Provision your Linux server and save the user credentials QR code.</li>
          <li>Scan the server QR code in the app, then scan the camera QR code.</li>
        </ol>

        <div class="help-links">
          <a class="help-link" href="/hardware-help" on:click={setHelpRef}>Recommended hardware guide</a>
          <a class="help-link" href="/ionos-help" on:click={setHelpRef}>Ionos VPS setup guide</a>
        </div>
      </section>
    {/if}
  </section>

  {#if pendingRoute}
    <div class="version-modal-backdrop" role="presentation">
      <div
        class="version-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="version-warning-title"
      >
        <h2 id="version-warning-title">{versionWarningTitle}</h2>
        <p>{versionWarningBody}</p>
        <div class="version-modal__actions">
          <button class="version-modal__button version-modal__button--secondary" type="button" on:click={closeVersionWarning}>
            Go back
          </button>
          <button class="version-modal__button version-modal__button--primary" type="button" on:click={continuePastVersionWarning}>
            Continue anyway
          </button>
        </div>
      </div>
    </div>
  {/if}
</main>

<style>
  :global(body) {
    margin: 0;
    background: #030303;
    color: #fff;
    font-family: Inter, "Segoe UI", sans-serif;
  }

  .page {
    min-height: 100vh;
    position: relative;
    overflow-x: hidden;
  }

  .page-backdrop {
    position: fixed;
    inset: 0;
    pointer-events: none;
    background:
      radial-gradient(760px 320px at 50% 102px, rgba(255, 255, 255, 0.015), transparent 68%),
      #030303;
  }

  .home-frame {
    --frame-pad: 24px;
    width: min(576px, calc(100% - 16px));
    margin: 0 auto;
    padding: 0 var(--frame-pad) 84px;
    box-sizing: border-box;
    position: relative;
  }

  .hero {
    min-height: 240px;
    width: calc(100% + (var(--frame-pad) * 2));
    margin-left: calc(var(--frame-pad) * -1);
    position: relative;
    text-align: center;
  }

  .hero-outline {
    position: absolute;
    left: 50%;
    top: 62px;
    width: 760px;
    height: 172.5px;
    transform: translateX(-50%);
    overflow: hidden;
    pointer-events: none;
    -webkit-mask-image: url("/deploy-assets/home-backdrop-mask-latest.svg");
    -webkit-mask-repeat: no-repeat;
    -webkit-mask-size: 100% 100%;
    -webkit-mask-mode: alpha;
    mask-image: url("/deploy-assets/home-backdrop-mask-latest.svg");
    mask-repeat: no-repeat;
    mask-size: 100% 100%;
    mask-mode: alpha;
  }

  .hero-outline img {
    position: absolute;
    left: 50%;
    top: -124px;
    width: 440px;
    height: 440px;
    transform: translateX(-50%);
    display: block;
  }

  .hero-mark-shell {
    width: 56px;
    height: 56px;
    margin: 56px auto 16px;
    position: relative;
    border-radius: 16px;
    box-shadow:
      0 0 0 1px rgba(255, 255, 255, 0.1),
      0 20px 25px -5px rgba(43, 127, 255, 0.1),
      0 8px 10px -6px rgba(43, 127, 255, 0.1);
  }

  .hero-mark {
    width: 56px;
    height: 56px;
    display: block;
    border-radius: 16px;
  }

  .hero-signal {
    width: 20px;
    height: 20px;
    position: absolute;
    right: -2px;
    bottom: -2px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 999px;
    background: #00bc7d;
    box-shadow: 0 0 0 2px #030303;
  }

  .hero-signal img {
    width: 10px;
    height: 10px;
    display: block;
  }

  h1 {
    margin: 0;
    color: #fff;
    font-size: 30px;
    font-weight: 700;
    line-height: 36px;
    letter-spacing: -0.75px;
  }

  .hero-meta {
    margin-top: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    flex-wrap: wrap;
    color: rgba(255, 255, 255, 0.4);
    font-size: 13px;
    line-height: 19.5px;
  }

  .meta-chip {
    height: 22.5px;
    padding: 0 8px;
    border-radius: 14px;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 11px;
    font-weight: 500;
    line-height: 16.5px;
  }

  .meta-chip img {
    width: 12px;
    height: 12px;
    display: block;
  }

  .meta-chip--time {
    color: #51a2ff;
    background: rgba(43, 127, 255, 0.1);
    border: 1px solid rgba(43, 127, 255, 0.2);
  }

  .meta-chip--e2ee {
    color: #00d492;
    background: rgba(0, 188, 125, 0.1);
    border: 1px solid rgba(0, 188, 125, 0.2);
  }

  .first-time {
    margin: 39px auto 0;
    width: 141.73px;
    height: 30.5px;
    padding: 0 13px 0 12px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-radius: 999px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(255, 255, 255, 0.03);
    color: rgba(255, 255, 255, 0.4);
    font: inherit;
    font-size: 11px;
    line-height: 16.5px;
    cursor: pointer;
    box-sizing: border-box;
  }

  .first-time img {
    width: 14px;
    height: 14px;
    display: block;
    flex: 0 0 auto;
  }

  .first-time__switch {
    margin-left: auto;
    width: 32px;
    height: 16px;
    padding: 2px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.1);
    box-sizing: border-box;
    transition: background 140ms ease;
  }

  .first-time__switch i {
    width: 12px;
    height: 12px;
    border-radius: 999px;
    background: #fff;
    display: block;
    box-shadow:
      0 1px 3px rgba(0, 0, 0, 0.1),
      0 1px 2px -1px rgba(0, 0, 0, 0.1);
    transition: transform 140ms ease;
  }

  .first-time__switch.enabled {
    background: rgba(0, 188, 125, 0.32);
  }

  .first-time__switch.enabled i {
    transform: translateX(16px);
  }

  .section-label {
    margin-top: 0;
    color: rgba(255, 255, 255, 0.3);
    font-size: 11px;
    font-weight: 600;
    line-height: 16.5px;
    letter-spacing: 0.55px;
    text-transform: uppercase;
  }

  .step-card {
    height: 78px;
    margin-top: 20px;
    position: relative;
    display: block;
    overflow: hidden;
    border-radius: 20px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    background: rgba(255, 255, 255, 0.02);
    text-decoration: none;
    color: inherit;
  }

  .step-card__bg {
    width: 128px;
    height: 128px;
    position: absolute;
    right: -24px;
    bottom: -24px;
    display: block;
    pointer-events: none;
  }

  .step-card__icon {
    width: 44px;
    height: 44px;
    position: absolute;
    left: 16px;
    top: 16px;
    border-radius: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .step-card__icon img {
    width: 20px;
    height: 20px;
    display: block;
  }

  .step-card__icon--one {
    background: rgba(43, 127, 255, 0.1);
  }

  .step-card__icon--two {
    background: rgba(0, 188, 125, 0.1);
  }

  .step-card__badge {
    width: 16px;
    height: 16px;
    position: absolute;
    left: 48px;
    top: 12px;
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #fff;
    font-size: 9px;
    font-weight: 700;
    line-height: 13.5px;
  }

  .step-card__badge--one {
    background: #2b7fff;
  }

  .step-card__badge--two {
    background: #00bc7d;
  }

  .step-card__copy {
    padding: 18px 48px 0 76px;
  }

  .step-card__title-row {
    display: flex;
    align-items: baseline;
    gap: 7px;
  }

  .step-card__title-row h2 {
    margin: 0;
    color: #fff;
    font-size: 14px;
    font-weight: 500;
    line-height: 21px;
  }

  .step-card__title-row span {
    color: rgba(255, 255, 255, 0.3);
    font-size: 11px;
    line-height: 16.5px;
  }

  .step-card__copy p {
    margin: 2px 0 0;
    color: rgba(255, 255, 255, 0.4);
    font-size: 12px;
    line-height: 18px;
  }

  .step-card__arrow {
    width: 16px;
    height: 16px;
    position: absolute;
    right: 18px;
    top: 31px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .step-card__arrow img {
    width: 16px;
    height: 16px;
    display: block;
  }

  .help-panel {
    margin-top: 24px;
    padding: 18px 20px;
    border-radius: 20px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    background: rgba(255, 255, 255, 0.02);
  }

  .quick-steps {
    margin: 0;
    padding-left: 18px;
    color: rgba(255, 255, 255, 0.7);
    font-size: 12px;
    line-height: 18px;
  }

  .quick-steps li + li {
    margin-top: 6px;
  }

  .help-links {
    margin-top: 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .help-link {
    color: rgba(81, 162, 255, 0.95);
    font-size: 12px;
    line-height: 18px;
    text-decoration: none;
  }

  .help-link:hover {
    text-decoration: underline;
  }

  .version-modal-backdrop {
    position: fixed;
    inset: 0;
    z-index: 60;
    display: grid;
    place-items: center;
    padding: 24px;
    background: rgba(0, 0, 0, 0.68);
    backdrop-filter: blur(10px);
  }

  .version-modal {
    width: min(420px, 100%);
    padding: 22px;
    border-radius: 18px;
    border: 1px solid rgba(255, 255, 255, 0.08);
    background: #101010;
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.45);
    box-sizing: border-box;
  }

  .version-modal h2 {
    margin: 0;
    color: #fff;
    font-size: 18px;
    font-weight: 650;
    line-height: 24px;
  }

  .version-modal p {
    margin: 10px 0 0;
    color: rgba(255, 255, 255, 0.68);
    font-size: 13px;
    line-height: 19.5px;
  }

  .version-modal__actions {
    margin-top: 20px;
    display: flex;
    justify-content: flex-end;
    gap: 10px;
  }

  .version-modal__button {
    height: 36px;
    padding: 0 14px;
    border-radius: 12px;
    border: 1px solid transparent;
    font: inherit;
    font-size: 12px;
    font-weight: 650;
    cursor: pointer;
  }

  .version-modal__button--secondary {
    background: rgba(255, 255, 255, 0.06);
    border-color: rgba(255, 255, 255, 0.08);
    color: rgba(255, 255, 255, 0.8);
  }

  .version-modal__button--primary {
    background: #f59e0b;
    color: #151008;
  }

  @media (max-width: 640px) {
    .home-frame {
      width: calc(100% - 16px);
      --frame-pad: 16px;
    }

    .hero-outline {
      width: min(760px, calc(100% + 136px));
    }

    .hero-meta {
      gap: 6px;
    }

    .step-card__copy {
      padding-right: 40px;
    }

    .step-card__title-row {
      flex-wrap: wrap;
      row-gap: 2px;
    }

    .version-modal__actions {
      flex-direction: column-reverse;
    }

    .version-modal__button {
      width: 100%;
    }
  }
</style>
