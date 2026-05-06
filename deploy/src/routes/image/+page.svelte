<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onMount } from "svelte";
  import { save } from "@tauri-apps/plugin-dialog";
  import { goto } from "$app/navigation";
  import { prepareImage } from "$lib/api";
  import { maskDemoText } from "$lib/demoDisplay";

  type DevSettings = {
    enabled: boolean;
    binariesSource: "main" | "custom";
    binariesRepo: string;
    key1Name: string;
    key1User: string;
    key2Name: string;
    key2User: string;
    githubToken: string;
    maskUserPathsWithDemo: boolean;
  };

  const SETTINGS_KEY = "secluso-dev-settings";
  const FIRST_TIME_KEY = "secluso-first-time";
  const imageBackIcon = "/deploy-assets/image-back-latest.svg";
  const imageHeroArt = "/deploy-assets/image-hero-latest.svg";
  const imageLocationIcon = "/deploy-assets/image-output-icon-latest.svg";
  const pickerIcon = "/deploy-assets/image-picker-icon-latest.svg";
  const qrLocationIcon = "/deploy-assets/image-qr-icon-latest.svg";
  const outputHelpIcon = "/deploy-assets/image-output-help-icon-latest.svg";
  const buildArrowIcon = "/deploy-assets/image-build-arrow-latest.svg";

  // config state
  let qrOutputPath = "";           // full file path from the os save dialog
  let imageOutputPath = "";        // full file path from the os save dialog
  let devSettings: DevSettings = {
    enabled: false,
    binariesSource: "main",
    binariesRepo: "",
    key1Name: "",
    key1User: "",
    key2Name: "",
    key2User: "",
    githubToken: "",
    maskUserPathsWithDemo: false
  };

  // progress state
  let preparing = false;
  let errorMsg = "";
  let firstTimeOn = false;
  $: imageOutputPlaceholder = "Choose file (e.g., secluso-rpi.wic)";

  async function pickQrOutput() {
    const path = await save({
      title: "Save pairing QR code as…",
      defaultPath: "camera-qr.png",
      filters: [ { name: "PNG image", extensions: ["png"] } ]
    });
    if (typeof path === "string" && path.length) qrOutputPath = path;
  }

  async function pickImageOutput() {
    const now = new Date();
    const stamp = [
      now.getFullYear(),
      String(now.getMonth() + 1).padStart(2, "0"),
      String(now.getDate()).padStart(2, "0"),
      "-",
      String(now.getHours()).padStart(2, "0"),
      String(now.getMinutes()).padStart(2, "0")
    ].join("");
    const defaultPath = `secluso-rpi-${stamp}.wic`;
    const path = await save({
      title: "Save Raspberry Pi image as…",
      defaultPath,
      filters: [ { name: "WIC image", extensions: ["wic"] } ]
    });
    if (typeof path === "string" && path.length) imageOutputPath = path;
  }

  function validate(): string | null {
    if (!qrOutputPath) return "Please choose where to save the QR code.";
    if (!imageOutputPath) return "Please choose where to save the image (.wic).";
    if (!imageOutputPath.endsWith(".wic")) return "Output image must end with .wic";
    if (!qrOutputPath.endsWith(".png")) return "QR code must end with .png";
    if (devSettings.enabled && devSettings.binariesSource === "custom") {
      if (!devSettings.binariesRepo.trim()) return "Custom repo URL is required.";
      if (!devSettings.key1Name.trim() || !devSettings.key1User.trim()) {
        return "Key 1 name and GitHub username are required.";
      }
      if (!devSettings.key2Name.trim() || !devSettings.key2User.trim()) {
        return "Key 2 name and GitHub username are required.";
      }
    }
    return null;
  }

  async function startBuild() {
    errorMsg = "";
    const err = validate();
    if (err) { errorMsg = err; return; }

    preparing = true;

    try {
      const { run_id } = await prepareImage({
        qrOutputPath,
        imageOutputPath,
        binariesRepo: devSettings.binariesSource === "custom" ? devSettings.binariesRepo.trim() : undefined,
        githubToken: devSettings.enabled && devSettings.githubToken.trim() ? devSettings.githubToken.trim() : undefined,
        sigKeys:
          devSettings.binariesSource === "custom"
            ? [
                { name: devSettings.key1Name.trim(), githubUser: devSettings.key1User.trim() },
                { name: devSettings.key2Name.trim(), githubUser: devSettings.key2User.trim() }
              ]
            : undefined
      });
      goto(`/status?mode=image&runId=${encodeURIComponent(run_id)}`);
    } catch (e: any) {
      errorMsg = e?.toString() ?? "Image preparation failed.";
    } finally {
      preparing = false;
    }
  }

  function goBack() { goto("/"); }

  onMount(() => {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw) as Partial<DevSettings>;
      devSettings = { ...devSettings, ...parsed };
    } catch {
        devSettings = {
          enabled: false,
          binariesSource: "main",
          binariesRepo: "",
          key1Name: "",
          key1User: "",
          key2Name: "",
          key2User: "",
          githubToken: "",
          maskUserPathsWithDemo: false
        };
    }
  });

  onMount(() => {
    const raw = localStorage.getItem(FIRST_TIME_KEY);
    if (raw === null) {
      firstTimeOn = true;
      return;
    }
    firstTimeOn = raw === "true";
  });

  function toggleFirstTime() {
    firstTimeOn = !firstTimeOn;
    localStorage.setItem(FIRST_TIME_KEY, String(firstTimeOn));
  }
</script>

<main class="page">
  <div class="backdrop"></div>
  <section class="frame">
    <div class="toolbar">
      <button class="back-link" on:click={goBack}>
        <img src={imageBackIcon} alt="" />
        <span>Back</span>
      </button>

      <label class="tips-toggle">
        <span>Show tips</span>
        <span class="tips-switch">
          <input type="checkbox" checked={firstTimeOn} on:change={toggleFirstTime} />
          <span class="tips-track"></span>
        </span>
      </label>
    </div>

    <div class="step-pill">Step 1</div>

    <div class="hero">
      <div class="hero-copy">
        <h1>Prepare Raspberry Pi Image</h1>
        <p>Download a verified Pi image and add the camera pairing secret.</p>
      </div>
      <img class="hero-art" src={imageHeroArt} alt="" />
    </div>

    <section class="section-block outputs">
      <div class="label">Output Locations</div>

      <div class="output-row">
        <div class="field-label">
          <img src={imageLocationIcon} alt="" />
          <span>Save Pi image (.wic) to</span>
        </div>
        <div class="output-picker">
          <div class="output-input">
            <input readonly placeholder={imageOutputPlaceholder} value={maskDemoText(imageOutputPath)} />
          </div>
          <button class="picker-button" on:click={pickImageOutput} aria-label="Choose image output path">
            <img src={pickerIcon} alt="" />
          </button>
        </div>
      </div>

      <div class="output-row">
        <div class="field-label">
          <img src={qrLocationIcon} alt="" />
          <span>Save camera QR code (.png) to</span>
        </div>
        <div class="output-picker">
          <div class="output-input">
            <input readonly placeholder="Choose where to save the QR code..." value={maskDemoText(qrOutputPath)} />
          </div>
          <button class="picker-button" on:click={pickQrOutput} aria-label="Choose QR output path">
            <img src={pickerIcon} alt="" />
          </button>
        </div>
      </div>

      {#if firstTimeOn}
        <div class="info-banner">
          <img src={outputHelpIcon} alt="" />
          <p>The <span>.wic file</span> is flashed to your SD card. The <span>QR code</span> is scanned by the mobile app to connect securely.</p>
        </div>
      {/if}
    </section>

    {#if errorMsg}
      <div class="alert error">{maskDemoText(errorMsg)}</div>
    {/if}

    <button class="primary" disabled={preparing} on:click={startBuild}>
      <span>{preparing ? "Preparing…" : "Prepare Image"}</span>
      <img src={buildArrowIcon} alt="" />
    </button>
    <p class="caption">This prepares a downloadable .wic file for Raspberry Pi Imager</p>
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
    position: relative;
    overflow: hidden;
    padding-bottom: 72px;
  }

  .backdrop {
    position: fixed;
    inset: 0;
    pointer-events: none;
    background:
      radial-gradient(780px 420px at 50% 132px, rgba(255, 255, 255, 0.016), transparent 68%),
      linear-gradient(180deg, rgba(3, 3, 3, 0.98), #030303 46%);
  }

  .frame {
    position: relative;
    z-index: 1;
    width: min(calc(100% - 48px), 528px);
    margin: 0 auto;
    padding-top: 24px;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .tips-toggle {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    color: rgba(255, 255, 255, 0.3);
    font-size: 11px;
    line-height: 16.5px;
  }

  .back-link {
    border: 0;
    background: transparent;
    padding: 0;
    color: rgba(255, 255, 255, 0.4);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font: inherit;
    font-size: 13px;
    line-height: 19.5px;
  }

  .back-link img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .tips-switch {
    position: relative;
    width: 24px;
    height: 13.8px;
    flex: 0 0 auto;
  }

  .tips-switch input {
    position: absolute;
    inset: 0;
    margin: 0;
    opacity: 0;
    cursor: pointer;
  }

  .tips-track {
    position: absolute;
    inset: 0;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.05);
    box-sizing: border-box;
    transition:
      background-color 140ms ease,
      border-color 140ms ease;
  }

  .tips-track::after {
    content: "";
    position: absolute;
    top: 0.9px;
    left: 0.9px;
    width: 12px;
    height: 12px;
    border-radius: 999px;
    background: #030303;
    transition: transform 140ms ease;
  }

  .tips-switch input:checked + .tips-track {
    background: #2b7fff;
    border-color: transparent;
  }

  .tips-switch input:checked + .tips-track::after {
    transform: translateX(10.25px);
  }

  .step-pill {
    display: inline-flex;
    align-items: center;
    height: 19px;
    margin-top: 39px;
    padding: 0 8px;
    border-radius: 14px;
    background: rgba(43, 127, 255, 0.1);
    color: #51a2ff;
    text-transform: uppercase;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.5px;
    line-height: 15px;
  }

  .hero {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 18px;
    margin-top: 12px;
  }

  h1 {
    margin: 0;
    font-size: 24px;
    line-height: 32px;
    font-weight: 600;
  }

  .hero p {
    margin: 12px 0 0;
    max-width: 492px;
    color: rgba(255, 255, 255, 0.4);
    font-size: 14px;
    line-height: 22.75px;
  }

  .hero-art {
    width: 160px;
    height: 160px;
    margin-top: -31px;
    margin-right: -16px;
    flex: 0 0 auto;
  }

  .label {
    color: rgba(255, 255, 255, 0.36);
    text-transform: uppercase;
    letter-spacing: 0.55px;
    font-size: 11px;
    font-weight: 500;
    line-height: 16.5px;
    margin-bottom: 12px;
  }

  .section-block {
    margin-top: 24px;
  }

  .outputs {
    margin-top: 42px;
  }

  .output-row + .output-row {
    margin-top: 20px;
  }

  .field-label {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 10px;
    color: rgba(255, 255, 255, 0.5);
    font-size: 12px;
    line-height: 18px;
  }

  .field-label img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .output-picker {
    display: grid;
    grid-template-columns: 1fr 50px;
    gap: 8px;
  }

  .output-input {
    height: 41.5px;
    border-radius: 16px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(255, 255, 255, 0.03);
    overflow: hidden;
    display: flex;
    align-items: center;
    padding: 0 12px;
  }

  .output-input input {
    width: 100%;
    height: 15.5px;
    padding: 0;
    border: 0;
    background: transparent;
    color: rgba(255, 255, 255, 0.88);
    font: inherit;
    font-size: 13px;
    line-height: 15.5px;
  }

  .output-input input::placeholder {
    color: rgba(255, 255, 255, 0.25);
  }

  .picker-button {
    width: 50px;
    height: 41.5px;
    border-radius: 16px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(255, 255, 255, 0.04);
    display: grid;
    place-items: center;
    cursor: pointer;
  }

  .picker-button img {
    width: 16px;
    height: 16px;
    display: block;
  }

  .info-banner {
    margin-top: 20px;
    min-height: 65px;
    padding: 12px;
    border-radius: 16px;
    border: 1px solid rgba(255, 255, 255, 0.04);
    background: rgba(255, 255, 255, 0.02);
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }

  .info-banner img {
    width: 16px;
    height: 16px;
    display: block;
    margin-top: 2px;
    flex: 0 0 auto;
  }

  .info-banner p {
    margin: 0;
    color: rgba(255, 255, 255, 0.4);
    font-size: 12px;
    line-height: 19.5px;
  }

  .info-banner span {
    color: rgba(255, 255, 255, 0.6);
  }

  .primary {
    width: 100%;
    height: 49px;
    margin-top: 28px;
    border-radius: 20px;
    border: none;
    background: #3b82f6;
    color: #fff;
    font: inherit;
    font-size: 14px;
    line-height: 21px;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    cursor: pointer;
  }

  .primary img {
    width: 16px;
    height: 16px;
    display: block;
  }

  button:disabled {
    opacity: 0.56;
    cursor: not-allowed;
  }

  .caption {
    margin: 12px 0 0;
    text-align: center;
    color: rgba(255, 255, 255, 0.25);
    font-size: 11px;
    line-height: 16.5px;
  }

  .alert {
    margin-top: 18px;
    padding: 12px 14px;
    border-radius: 16px;
    border: 1px solid rgba(248, 113, 113, 0.24);
    background: rgba(127, 29, 29, 0.25);
    color: #fecaca;
    font-size: 13px;
    line-height: 19.5px;
  }

  @media (max-width: 640px) {
    .frame {
      width: calc(100% - 28px);
    }

    .hero {
      gap: 10px;
    }

    .hero-art {
      width: 128px;
      height: 128px;
      margin-top: -18px;
      margin-right: -10px;
    }
  }
</style>
