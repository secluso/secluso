<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { page } from "$app/stores";
  import { goto } from "$app/navigation";
  import { listenProvisionEvents, type ProvisionEvent } from "$lib/api";
  import { maskDemoText } from "$lib/demoDisplay";

  type StepState = "pending" | "running" | "ok" | "error";
  type LogTone = "info" | "warn" | "error" | "success";

  const stepMap: Record<string, { key: string; title: string }[]> = {
    server: [
      { key: "ssh_connect", title: "Connect via SSH" },
      { key: "preflight", title: "Check server compatibility" },
      { key: "detect", title: "Detect install state" },
      { key: "artifacts", title: "Fetch verified binaries" },
      { key: "secrets", title: "Prepare runtime secrets" },
      { key: "remote", title: "Run remote installer" },
      { key: "health", title: "Check public health" }
    ],
    image: [
      { key: "validate", title: "Validate inputs" },
      { key: "credentials", title: "Generate secrets" },
      { key: "image_download", title: "Prepare base image" },
      { key: "inject", title: "Inject config" },
      { key: "verify", title: "Finalize" }
    ]
  };

  let runId = "";
  let mode = "server";
  let steps: { key: string; title: string }[] = [];
  let stepStatus: Record<string, StepState> = {};
  let logs: { level: string; step?: string; line: string; time: string }[] = [];
  let doneOk: boolean | null = null;
  let unlisten: (() => void) | null = null;
  let lastRunId = "";
  let updaterWarning: string | null = null;
  let firstTimeOn = false;
  let showLogs = false;

  const FIRST_TIME_KEY = "secluso-first-time";
  const statusBackIcon = "/deploy-assets/status-back-latest.svg";
  const statusTipsIcon = "/deploy-assets/status-guided-tips-icon-latest.svg";
  const statusInfoIcon = "/deploy-assets/status-info-icon-latest.svg";
  const statusLogsIcon = "/deploy-assets/status-view-logs-icon-latest.svg";
  const statusDoneIcon = "/deploy-assets/status-done-icon-latest.svg";
  const statusHeroArtImage = "/deploy-assets/status-hero-latest.svg";
  const statusHeroStateIcon = "/deploy-assets/status-state-icon-latest.svg";
  const logsHeaderIcon = "/deploy-assets/status-logs-header-icon-latest.svg";
  const logsCopyIcon = "/deploy-assets/status-copy-icon-latest.svg";

  $: {
    runId = $page.url.searchParams.get("runId") ?? "";
    mode = $page.url.searchParams.get("mode") ?? "server";
  }
  $: steps = stepMap[mode] ?? stepMap.server;

  $: if (runId && runId !== lastRunId) {
    lastRunId = runId;
    resetState();
    startListening();
  }

  $: completedSteps = steps.filter((s) => stepStatus[s.key] === "ok").length;
  $: totalSteps = steps.length;
  $: progress = totalSteps ? Math.round((completedSteps / totalSteps) * 100) : 0;
  $: progressValue = doneOk === true ? 100 : progress;
  $: heroTitle = mode === "image" ? "Image Ready" : "Server Ready";
  $: heroArt = mode === "image" ? statusHeroArtImage : "/deploy-assets/status-hero.svg";
  $: statusLeadLabel =
    doneOk === true
      ? "COMPLETED"
      : doneOk === false
      ? mode === "image"
        ? "BUILD FAILED"
        : "DEPLOY FAILED"
      : mode === "image"
        ? "BUILDING..."
        : "DEPLOYING...";
  $: logsTitle = mode === "image" ? "Build Logs" : "Provision Logs";
  $: logsFileName = mode === "image" ? "build.log" : "provision.log";
  $: guidanceText =
    mode === "image"
      ? "The build typically takes 2-5 minutes. Your image will include encryption keys and auto-updater configuration."
      : "Provisioning typically takes 2-5 minutes. Secluso installs the verified server binaries, configures the service, and checks public reachability.";
  $: logText = logs.map((log) => `${log.time} ${log.step ?? "general"} ${maskDemoText(log.line)}`).join("\n");

  function resetState() {
    stepStatus = {};
    for (const s of steps) stepStatus[s.key] = "pending";
    if (steps.some((s) => s.key === "validate")) {
      stepStatus = { ...stepStatus, validate: "ok" };
    }
    logs = [];
    doneOk = null;
    updaterWarning = null;
    showLogs = false;
  }

  async function startListening() {
    if (unlisten) unlisten();
    unlisten = await listenProvisionEvents((evt) => handleEvent(evt));
  }

  function handleEvent(evt: ProvisionEvent) {
    if (evt.run_id !== runId) return;

    if (evt.type === "step_start") {
      steps = steps.map((step) => (step.key === evt.step ? { ...step, title: evt.title } : step));
      stepStatus = { ...stepStatus, [evt.step]: "running" };
      return;
    }

    if (evt.type === "step_ok") {
      stepStatus = { ...stepStatus, [evt.step]: "ok" };
      return;
    }

    if (evt.type === "step_error") {
      stepStatus = { ...stepStatus, [evt.step]: "error" };
      logs = [
        ...logs,
        { level: "error", step: evt.step, line: evt.message, time: new Date().toLocaleTimeString() }
      ];
      return;
    }

    if (evt.type === "log") {
      logs = [
        ...logs,
        { level: evt.level, step: evt.step, line: evt.line, time: new Date().toLocaleTimeString() }
      ];
      if (
        evt.level === "warn" &&
        evt.step === "updater" &&
        !updaterWarning &&
        evt.line.includes("secluso-updater not found")
      ) {
        updaterWarning = "secluso-updater was not found, so auto updates were not set up.";
      }
      return;
    }

    if (evt.type === "done") {
      doneOk = evt.ok;
    }
  }

  function onBack() {
    if (showLogs) {
      showLogs = false;
      return;
    }
    goto("/");
  }

  async function copyLogs() {
    if (!logText) return;
    try {
      await navigator.clipboard.writeText(logText);
    } catch {
      // ignore clipboard errors
    }
  }

  function toggleFirstTime() {
    firstTimeOn = !firstTimeOn;
    localStorage.setItem(FIRST_TIME_KEY, String(firstTimeOn));
  }

  function stepStateLabel(state: StepState) {
    if (state === "ok") return "Done";
    if (state === "error") return "Failed";
    return "";
  }

  function logTone(log: { level: string; line: string }): LogTone {
    const normalized = log.line.toLowerCase();

    if (
      normalized.includes("complete") ||
      normalized.includes("generated") ||
      normalized.includes("saved") ||
      normalized.includes("healthy") ||
      normalized.includes("succeeded") ||
      normalized.includes("success")
    ) {
      return "success";
    }

    if (
      normalized.includes("fatal") ||
      normalized.includes("failed") ||
      normalized.includes("error:") ||
      normalized.includes("can't ") ||
      normalized.includes("cannot ") ||
      normalized.includes("permission denied") ||
      normalized.includes("not found") ||
      normalized.includes("missing ")
    ) {
      return "error";
    }

    if (
      log.level === "warn" ||
      normalized.includes("warning") ||
      normalized.includes("warn:") ||
      normalized.includes("unable to") ||
      normalized.includes("falling back") ||
      normalized.includes("fallback")
    ) {
      return "warn";
    }

    return "info";
  }

  onDestroy(() => {
    if (unlisten) unlisten();
  });

  onMount(() => {
    const raw = localStorage.getItem(FIRST_TIME_KEY);
    if (raw === null) {
      firstTimeOn = true;
      return;
    }
    firstTimeOn = raw === "true";
  });
</script>

<main class="page">
  {#if doneOk === false}
    <div class="overlay" role="status" aria-live="polite">
      <div class="modal error">
        <div class="modal-title">{mode === "image" ? "Build failed" : "Deployment failed"}</div>
        <div class="modal-body">Something went wrong. Check the logs for details.</div>
        <button class="modal-btn" on:click={() => (doneOk = null)}>Dismiss</button>
      </div>
    </div>
  {/if}

  {#if updaterWarning}
    <div class="overlay" role="status" aria-live="polite">
      <div class="modal warn">
        <div class="modal-title">Updater not set up</div>
        <div class="modal-body">{maskDemoText(updaterWarning)}</div>
        <button class="modal-btn" on:click={() => (updaterWarning = null)}>Dismiss</button>
      </div>
    </div>
  {/if}

  <section class="frame">
    <div class="toolbar">
      <button class="back-link" on:click={onBack}>
        <img src={statusBackIcon} alt="" />
        <span>Back</span>
      </button>
    </div>

    {#if !runId}
      <section class="missing-card">
        <h1>Missing run ID</h1>
        <p>Start a provisioning or image preparation task first, then return here.</p>
      </section>
    {:else if showLogs}
      <div class="logs-view">
        <div class="logs-head">
          <div class="logs-title-block">
            <span class="logs-title-icon">
              <img src={logsHeaderIcon} alt="" />
            </span>
            <div class="logs-copy">
              <h1>{logsTitle}</h1>
              <p>{logs.length} entries</p>
            </div>
          </div>

          <button class="copy-button" on:click={copyLogs}>
            <img src={logsCopyIcon} alt="" />
            <span>Copy</span>
          </button>
        </div>

        <section class="terminal-panel">
          <div class="terminal-bar">
            <div class="terminal-dots">
              <span></span>
              <span></span>
              <span></span>
            </div>
            <strong>{logsFileName}</strong>
          </div>

          <div class="terminal-body">
            {#if logs.length === 0}
              <div class="terminal-empty">No log output yet.</div>
            {:else}
              {#each logs as log}
                <div class={`log-line ${logTone(log)}`}>
                  <span class="time">{log.time}</span>
                  <span class="log-dot"></span>
                  <span class="message">{maskDemoText(log.line)}</span>
                </div>
              {/each}
              <div class="terminal-cursor"></div>
            {/if}
          </div>
        </section>
      </div>
    {:else}
      <div class="hero-status">
        <span class="hero-status-icon">
          <img src={statusHeroStateIcon} alt="" />
        </span>
        <span class="hero-status-label">{statusLeadLabel}</span>
      </div>

      <div class="hero">
        <div class="hero-copy">
          <h1>{heroTitle}</h1>
          <p class="run-id">
            <span>Run ID:</span>
            <code>{runId}</code>
          </p>
        </div>
        <img class="hero-art" src={heroArt} alt="" />
      </div>

      <div class="guidance-row">
        <div class="guidance-label">
          <img src={statusTipsIcon} alt="" />
          <span>Show guided tips</span>
        </div>

        <label class="guidance-switch" aria-label="Show guided tips">
          <input type="checkbox" checked={firstTimeOn} on:change={toggleFirstTime} />
          <span class="guidance-track">
            <span class="guidance-thumb"></span>
          </span>
        </label>
      </div>

      {#if firstTimeOn}
        <section class="notice-card">
          <img src={statusInfoIcon} alt="" />
          <p>{guidanceText}</p>
        </section>
      {/if}

      <section class="progress-card">
        <div class="progress-head">
          <div class="progress-summary">
            <strong>{progressValue}%</strong>
            <span>{completedSteps} of {totalSteps} steps</span>
          </div>

          <button class="logs-link" on:click={() => (showLogs = true)}>
            <img src={statusLogsIcon} alt="" />
            <span>View Logs</span>
          </button>
        </div>

        <div class="progress-bar">
          <div class="progress-fill" style={`width:${progressValue}%;`}></div>
        </div>
      </section>

      <section class="steps-list">
        {#each steps as s}
          <div class={`step ${stepStatus[s.key]}`}>
            {#if stepStatus[s.key] === "ok"}
              <span class="step-check">
                <img src={statusDoneIcon} alt="" />
              </span>
            {:else}
              <span class={`step-dot ${stepStatus[s.key]}`}></span>
            {/if}

            <span class="step-title">{s.title}</span>
            <span class={`step-state ${stepStatus[s.key]}`}>{stepStateLabel(stepStatus[s.key])}</span>
          </div>
        {/each}
      </section>
    {/if}
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    background: #000;
    color: #fff;
    font-family: Inter, "Segoe UI", sans-serif;
  }

  :global(button),
  :global(input) {
    font: inherit;
  }

  .page {
    min-height: 100vh;
    background: #000;
    color: #fff;
  }

  .frame {
    width: min(100%, 528px);
    margin: 0 auto;
    padding: 24px 24px 56px;
    box-sizing: border-box;
  }

  .toolbar {
    margin-bottom: 32px;
  }

  .back-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 0;
    border: 0;
    background: transparent;
    color: rgba(255, 255, 255, 0.4);
    font-size: 13px;
    line-height: 19.5px;
    cursor: pointer;
  }

  .back-link img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .hero-status {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 18px;
  }

  .hero-status-icon {
    width: 40px;
    height: 40px;
    border-radius: 16px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: rgba(43, 127, 255, 0.1);
  }

  .hero-status-icon img {
    width: 20px;
    height: 20px;
    display: block;
  }

  .hero-status-label {
    color: rgba(81, 162, 255, 0.8);
    font-size: 11px;
    font-weight: 500;
    line-height: 16.5px;
    letter-spacing: 0.55px;
    text-transform: uppercase;
  }

  .hero {
    position: relative;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 22px;
    min-height: 126px;
  }

  .hero-copy h1,
  .logs-copy h1,
  .missing-card h1 {
    margin: 0;
    font-size: 30px;
    font-weight: 600;
    line-height: 36px;
    letter-spacing: -0.75px;
  }

  .run-id {
    display: flex;
    align-items: center;
    gap: 0;
    margin: 11px 0 0;
    color: rgba(255, 255, 255, 0.4);
    font-size: 13px;
    line-height: 19.5px;
  }

  .run-id code {
    margin-left: 1px;
    color: rgba(255, 255, 255, 0.5);
    font-size: 13px;
    font-family: Menlo, Monaco, "Courier New", monospace;
    background: transparent;
  }

  .hero-art {
    width: 128px;
    height: 128px;
    margin-right: -16px;
    flex: 0 0 auto;
    object-fit: contain;
    opacity: 1;
  }

  .guidance-row {
    height: 53.5px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.04);
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  }

  .guidance-label {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    color: rgba(255, 255, 255, 0.5);
    font-size: 13px;
    line-height: 19.5px;
  }

  .guidance-label img {
    width: 16px;
    height: 16px;
    display: block;
  }

  .guidance-switch {
    position: relative;
    display: inline-flex;
    align-items: center;
    cursor: pointer;
  }

  .guidance-switch input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }

  .guidance-track {
    width: 28.8px;
    height: 16.56px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.05);
    transition: background-color 140ms ease;
    display: inline-flex;
    align-items: center;
    padding: 1.08px;
    box-sizing: border-box;
  }

  .guidance-thumb {
    width: 14.4px;
    height: 14.4px;
    border-radius: 999px;
    background: #030303;
    transition: transform 140ms ease;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
  }

  .guidance-switch input:checked + .guidance-track {
    background: #2b7fff;
    border-color: transparent;
  }

  .guidance-switch input:checked + .guidance-track .guidance-thumb {
    transform: translateX(11.16px);
  }

  .notice-card,
  .progress-card,
  .terminal-panel,
  .missing-card {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.04);
    box-sizing: border-box;
  }

  .notice-card {
    margin-top: 32px;
    padding: 16px 16px 17px;
    border-radius: 20px;
    display: flex;
    align-items: flex-start;
    gap: 12px;
  }

  .notice-card img {
    width: 16px;
    height: 16px;
    margin-top: 2px;
    flex: 0 0 auto;
  }

  .notice-card p,
  .missing-card p {
    margin: 0;
    color: rgba(255, 255, 255, 0.4);
    font-size: 13px;
    line-height: 21.13px;
  }

  .progress-card {
    margin-top: 32px;
    padding: 20px;
    border-radius: 16px;
    border-color: rgba(255, 255, 255, 0.05);
  }

  .progress-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .progress-summary {
    display: inline-flex;
    align-items: baseline;
    gap: 12px;
  }

  .progress-summary strong {
    font-size: 24px;
    font-weight: 600;
    line-height: 32px;
    color: #fff;
  }

  .progress-summary span {
    color: rgba(255, 255, 255, 0.3);
    font-size: 13px;
    line-height: 19.5px;
  }

  .logs-link,
  .copy-button,
  .modal-btn {
    border: 0;
    cursor: pointer;
  }

  .logs-link {
    padding: 0;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: transparent;
    color: #51a2ff;
    font-size: 12px;
    line-height: 18px;
  }

  .logs-link img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .progress-bar {
    width: 100%;
    height: 6px;
    margin-top: 16px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.05);
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    border-radius: 999px;
    background: linear-gradient(90deg, #3b82f6 0%, #60a5fa 50%, #3b82f6 100%);
  }

  .steps-list {
    margin-top: 34px;
    display: grid;
    gap: 18px;
  }

  .step {
    display: grid;
    grid-template-columns: 20px 1fr auto;
    align-items: center;
    gap: 12px;
    min-height: 26px;
  }

  .step-check {
    width: 20px;
    height: 20px;
    border-radius: 999px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 188, 125, 0.15);
  }

  .step-check img {
    width: 12px;
    height: 12px;
    display: block;
  }

  .step-dot {
    width: 8px;
    height: 8px;
    margin-left: 6px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.1);
  }

  .step-dot.running {
    background: #3b82f6;
  }

  .step-dot.error {
    background: rgba(255, 100, 103, 0.9);
  }

  .step-title {
    color: rgba(255, 255, 255, 0.25);
    font-size: 13px;
    line-height: 19.5px;
  }

  .step.ok .step-title,
  .step.running .step-title,
  .step.error .step-title {
    color: rgba(255, 255, 255, 0.6);
  }

  .step-state {
    min-width: 34px;
    text-align: right;
    font-size: 10px;
    line-height: 15px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }

  .step-state.ok {
    color: rgba(0, 212, 146, 0.6);
  }

  .step-state.error {
    color: rgba(255, 100, 103, 0.9);
  }

  .logs-view {
    display: grid;
    gap: 32px;
  }

  .logs-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
  }

  .logs-title-block {
    display: flex;
    align-items: flex-start;
    gap: 12px;
  }

  .logs-title-icon {
    width: 40px;
    height: 40px;
    border-radius: 16px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: rgba(43, 127, 255, 0.1);
  }

  .logs-title-icon img {
    width: 20px;
    height: 20px;
    display: block;
  }

  .logs-copy p {
    margin: 2px 0 0;
    color: rgba(255, 255, 255, 0.3);
    font-size: 12px;
    line-height: 18px;
  }

  .copy-button {
    height: 32px;
    padding: 0 12px;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    border-radius: 16px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.06);
    color: rgba(255, 255, 255, 0.5);
    font-size: 12px;
    line-height: 18px;
    box-sizing: border-box;
  }

  .copy-button img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .terminal-panel {
    overflow: hidden;
    border-radius: 16px;
    border-color: rgba(255, 255, 255, 0.05);
  }

  .terminal-bar {
    height: 37.5px;
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 0 16px;
    box-sizing: border-box;
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  }

  .terminal-dots {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .terminal-dots span {
    width: 10px;
    height: 10px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.1);
  }

  .terminal-bar strong {
    color: rgba(255, 255, 255, 0.2);
    font-size: 11px;
    line-height: 16.5px;
    font-weight: 400;
  }

  .terminal-body {
    max-height: 400px;
    overflow: auto;
    padding: 16px 16px 28px;
    box-sizing: border-box;
    background: rgba(0, 0, 0, 0.12);
  }

  .terminal-empty {
    color: rgba(255, 255, 255, 0.3);
    font-size: 12px;
    line-height: 18px;
  }

  .log-line {
    display: grid;
    grid-template-columns: 56px 6px 1fr;
    align-items: center;
    gap: 12px;
    min-height: 28.7px;
    font-family: Menlo, Monaco, "Courier New", monospace;
    font-size: 11px;
    line-height: 18.7px;
  }

  .time {
    color: rgba(255, 255, 255, 0.15);
    text-align: right;
  }

  .log-dot {
    width: 6px;
    height: 6px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.15);
  }

  .message {
    color: rgba(255, 255, 255, 0.4);
    overflow-wrap: anywhere;
  }

  .log-line.warn .log-dot {
    background: #ffb900;
  }

  .log-line.warn .message {
    color: rgba(255, 185, 0, 0.9);
  }

  .log-line.error .log-dot {
    background: #ff6467;
  }

  .log-line.error .message {
    color: rgba(255, 100, 103, 0.9);
  }

  .log-line.success .log-dot {
    background: #00d492;
  }

  .log-line.success .message {
    color: rgba(0, 212, 146, 0.9);
  }

  .terminal-cursor {
    width: 2px;
    height: 14px;
    margin: 7px 0 0 68px;
    border-radius: 999px;
    background: rgba(81, 162, 255, 0.8);
  }

  .missing-card {
    padding: 20px;
    border-radius: 16px;
  }

  .missing-card p {
    margin-top: 12px;
  }

  .overlay {
    position: fixed;
    inset: 0;
    display: grid;
    place-items: center;
    background: rgba(0, 0, 0, 0.7);
    z-index: 30;
    padding: 24px;
    box-sizing: border-box;
  }

  .modal {
    width: min(100%, 380px);
    padding: 20px;
    border-radius: 16px;
    background: #090909;
    border: 1px solid rgba(255, 255, 255, 0.08);
    box-shadow: 0 22px 60px rgba(0, 0, 0, 0.45);
    box-sizing: border-box;
  }

  .modal.ok {
    border-color: rgba(0, 212, 146, 0.2);
  }

  .modal.error {
    border-color: rgba(255, 100, 103, 0.22);
  }

  .modal.warn {
    border-color: rgba(255, 185, 0, 0.22);
  }

  .modal-title {
    font-size: 18px;
    font-weight: 600;
    line-height: 24px;
  }

  .modal-body {
    margin-top: 10px;
    color: rgba(255, 255, 255, 0.58);
    font-size: 13px;
    line-height: 19.5px;
  }

  .modal-btn {
    margin-top: 18px;
    height: 36px;
    padding: 0 14px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.06);
    color: rgba(255, 255, 255, 0.82);
  }

  @media (max-width: 640px) {
    .frame {
      padding-inline: 16px;
    }

    .hero {
      min-height: 0;
      flex-direction: column;
    }

    .hero-art {
      margin-right: 0;
      align-self: flex-end;
    }

    .progress-head,
    .logs-head {
      flex-direction: column;
      align-items: stretch;
    }

    .copy-button {
      justify-content: center;
    }

    .log-line {
      grid-template-columns: 1fr;
      gap: 4px;
    }

    .time {
      text-align: left;
    }

    .terminal-cursor {
      margin-left: 0;
    }
  }
</style>
