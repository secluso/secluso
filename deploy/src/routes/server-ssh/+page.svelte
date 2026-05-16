<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script lang="ts">
  import { goto } from "$app/navigation";
  import { onDestroy, onMount } from "svelte";
  import { open, save } from "@tauri-apps/plugin-dialog";
  import {
    checkSshPasswordAuth,
    disableSshPasswordAuth,
    fetchServerHostKey,
    generateSshKeypair,
    getDefaultSshKeyPath,
    installSshPublicKey,
    listenProvisionEvents,
    testServerSsh,
    provisionServer,
    type HostKeyProof,
    type KeyGenResult,
    type ProvisionEvent,
    type ServerRuntimePlan,
    type SshTarget,
    type ServerPlan
  } from "$lib/api";
  import { maskDemoText } from "$lib/demoDisplay";

  let host = "";
  let port = 22;
  let user = "root";

  type AuthMode = "password" | "keyfile" | "keypaste";
  let authMode: AuthMode = "password";
  let password = "";
  let keyPath = "";
  let keyText = "";
  let keyPassphrase = "";

  let useSameForSudo = true;
  let sudoPassword = "";

  let overwriteInstall = false;
  let serviceAccountKeyPath = "";
  let showFcmSection = false;
  let userCredentialsQrPath = "";
  let advancedNetworkMode = false;
  type AccessMode = "direct" | "proxy";
  let accessMode: AccessMode = "direct";
  let directPublicAddress = "";
  let directListenPort = 8000;
  let allowUfwRule = false;
  let proxyPublicUrl = "";
  let proxyListenPort = 18000;

  type DevSettings = {
    enabled: boolean;
    binariesSource: "main" | "custom";
    binariesRepo: string;
    customWicPath: string;
    key1Name: string;
    key1User: string;
    key2Name: string;
    key2User: string;
    githubToken: string;
    manifestVersionOverride: string;
    maskUserPathsWithDemo: boolean;
  };

  const SETTINGS_KEY = "secluso-dev-settings";
  const FIRST_TIME_KEY = "secluso-first-time";
  const defaultDevSettings: DevSettings = {
    enabled: false,
    binariesSource: "main",
    binariesRepo: "",
    customWicPath: "",
    key1Name: "",
    key1User: "",
    key2Name: "",
    key2User: "",
    githubToken: "",
    manifestVersionOverride: "",
    maskUserPathsWithDemo: false
  };
  let devSettings: DevSettings | null = null;
  let firstTimeOn = false;

  let testing = false;
  let provisioning = false;
  let fetchingHostKey = false;
  let errorMsg = "";
  let testResult: "ok" | "error" | null = null;
  let testMessage = "";
  let activeTestRunId = "";
  let testProgressTitle = "";
  let testProgressDetail = "";
  let hostKeyProof: HostKeyProof | null = null;
  let hostKeyConfirmed = false;
  let currentTargetKey = "";
  let verifiedTargetKey = "";
  let unlistenProvision: (() => void) | null = null;

  // SSH key generation
  let generatingKey = false;
  let generatedKey: KeyGenResult | null = null;
  let keyGenResult: "ok" | "error" | null = null;
  let keyGenMessage = "";
  let keyGenPromptOpen = false;
  let keyGenPassphrase = "";
  let keyGenPassphraseConfirm = "";
  let keyGenPromptError = "";

  // Password-auth hardening
  let checkingPasswordAuth = false;
  let disablingPasswordAuth = false;
  let passwordAuthEnabled: boolean | null = null;
  let passwordAuthMessage = "";
  // When using SSH key auth and the server still allows password logins, ask the user once per successful preflight whether to disable it
  let disablePrompt: "ask" | "running" | "done" | null = null;
  let disablePromptOutcome: "ok" | "error" | "dismissed" | null = null;
  let disablePromptError = "";

  $: currentTargetKey = `${host.trim()}:${port}`;
  $: if (verifiedTargetKey && currentTargetKey !== verifiedTargetKey) {
    hostKeyProof = null;
    hostKeyConfirmed = false;
    verifiedTargetKey = "";
  }

  // We used to gate the manual "Disable password auth" button on a strict
  // client-side state machine (authMode === key && lastTestedAuthMode === key
  // && preflight ok). Svelte reactivity ordering kept tripping over it and the
  // button stayed disabled even when conditions looked correct. The backend
  // now does a hard safety check — it refuses to disable password auth unless
  // ~/.ssh/authorized_keys has at least one entry — so the UI no longer
  // needs to be precious about gating the click. Worst case: click is
  // rejected with a clear "no keys configured" error.

  function goBack() {
    goto("/");
  }

  async function pickKeyFile() {
    try {
      const path = await open({
        title: "Choose private key file",
        multiple: false,
        directory: false
      });
      if (typeof path === "string") keyPath = path;
      if (Array.isArray(path) && path.length) keyPath = path[0];
    } catch (e: any) {
      errorMsg = e?.toString() ?? "Failed to open file picker.";
    }
  }

  async function pickServiceAccountKey() {
    try {
      const path = await open({
        title: "Choose service account key (JSON)",
        multiple: false,
        directory: false,
        filters: [{ name: "JSON", extensions: ["json"] }]
      });
      if (typeof path === "string") serviceAccountKeyPath = path;
      if (Array.isArray(path) && path.length) serviceAccountKeyPath = path[0];
    } catch (e: any) {
      errorMsg = e?.toString() ?? "Failed to open file picker.";
    }
  }

  function validateTarget(): string | null {
    if (!host.trim()) return "Server host/IP is required.";
    if (port < 1 || port > 65535) return "Port must be between 1 and 65535.";
    if (!hostKeyProof) return "Fetch the SSH host fingerprint before continuing.";
    if (!hostKeyConfirmed) return "Verify the SSH host fingerprint before continuing.";
    if (!user.trim()) return "Username is required.";
    if (authMode === "password" && !password) return "Password is required.";
    if (authMode === "keyfile" && !keyPath) return "Select a private key file.";
    if (authMode === "keypaste" && !keyText.trim()) return "Paste a private key.";
    if (!useSameForSudo && !sudoPassword) return "Enter sudo password or toggle same-as-login.";
    const runtime = buildRuntimePlan();
    if (runtime.listenPort < 1 || runtime.listenPort > 65535) return "Secluso listen port must be between 1 and 65535.";
    if (effectiveAccessMode() === "proxy" && !proxyPublicUrl.trim()) return "Enter the public URL already served by your reverse proxy.";
    return null;
  }

  function effectiveAccessMode(): AccessMode {
    return advancedNetworkMode ? accessMode : "direct";
  }

  function buildAuth(): SshTarget["auth"] {
    if (authMode === "password") {
      return { kind: "password", password };
    }
    if (authMode === "keyfile") {
      return {
        kind: "keyfile",
        path: keyPath,
        passphrase: keyPassphrase.trim() ? keyPassphrase : undefined
      };
    }
    return {
      kind: "keytext",
      text: keyText,
      passphrase: keyPassphrase.trim() ? keyPassphrase : undefined
    };
  }

  function buildTarget(): SshTarget {
    return {
      host: host.trim(),
      port,
      user: user.trim(),
      auth: buildAuth(),
      sudo: {
        mode: useSameForSudo ? "same" : "password",
        password: useSameForSudo ? undefined : sudoPassword
      },
      expectedHostKey: hostKeyConfirmed && hostKeyProof ? hostKeyProof : undefined
    };
  }

  function hostKeyPublicFilePath(proof: HostKeyProof | null): string | null {
    if (!proof) return null;
    switch (proof.algorithm) {
      case "ssh-ed25519":
        return "/etc/ssh/ssh_host_ed25519_key.pub";
      case "ssh-rsa":
        return "/etc/ssh/ssh_host_rsa_key.pub";
      case "ecdsa-sha2-nistp256":
      case "ecdsa-sha2-nistp384":
      case "ecdsa-sha2-nistp521":
        return "/etc/ssh/ssh_host_ecdsa_key.pub";
      case "ssh-dss":
        return "/etc/ssh/ssh_host_dsa_key.pub";
      default:
        // Keep the UI honest when libssh2 reports a key type we do not yet map
        // to a standard OpenSSH host key filename.
        return null;
    }
  }

  function hostKeyVerifyCommand(proof: HostKeyProof | null): string | null {
    // Show the exact ssh-keygen command for the presented host key type so the user does not have to guess which /etc/ssh/*.pub file to inspect.
    const path = hostKeyPublicFilePath(proof);
    return path ? `ssh-keygen -lf ${path}` : null;
  }

  async function onFetchHostKey() {
    errorMsg = "";
    testResult = null;
    const trimmedHost = host.trim();
    if (!trimmedHost) {
      errorMsg = "Server host/IP is required.";
      return;
    }
    if (port < 1 || port > 65535) {
      errorMsg = "Port must be between 1 and 65535.";
      return;
    }

    fetchingHostKey = true;
    try {
      hostKeyProof = await fetchServerHostKey({ host: trimmedHost, port });
      hostKeyConfirmed = false;
      verifiedTargetKey = `${trimmedHost}:${port}`;
    } catch (e: any) {
      hostKeyProof = null;
      hostKeyConfirmed = false;
      verifiedTargetKey = "";
      errorMsg = e?.toString() ?? "Failed to fetch the SSH host fingerprint.";
    } finally {
      fetchingHostKey = false;
    }
  }

  function buildRuntimePlan(): ServerRuntimePlan {
    if (effectiveAccessMode() === "proxy") {
      return {
        exposureMode: "proxy",
        bindAddress: "127.0.0.1",
        listenPort: proxyListenPort,
        allowUfwRule: false
      };
    }
    return {
      exposureMode: "direct",
      bindAddress: "0.0.0.0",
      listenPort: directListenPort,
      allowUfwRule
    };
  }

  function buildCredentialsServerUrl(): string {
    const runtime = buildRuntimePlan();
    const mode = effectiveAccessMode();
    const candidate =
      mode === "proxy"
        ? proxyPublicUrl.trim()
        : (advancedNetworkMode ? directPublicAddress.trim() : "") || host.trim();
    if (!candidate) return "";

    const withScheme =
      candidate.startsWith("http://") || candidate.startsWith("https://")
        ? candidate
        : mode === "proxy"
        ? `https://${candidate}`
        : `http://${candidate}`;

    try {
      const url = new URL(withScheme);
      if (mode === "direct" && !url.port) {
        url.port = String(runtime.listenPort);
      }
      return url.toString().replace(/\/$/, "");
    } catch {
      return withScheme.replace(/\/$/, "");
    }
  }

  function credentialsUrlWarning(urlValue: string): string | null {
    if (!urlValue) return null;
    try {
      const url = new URL(urlValue);
      const runtime = buildRuntimePlan();
      if (effectiveAccessMode() === "direct") {
        if (url.protocol === "https:") {
          return "Direct mode serves Secluso over plain HTTP on the server port.";
        }
        const effectivePort = Number(url.port || (url.protocol === "https:" ? 443 : 80));
        if (effectivePort !== runtime.listenPort) {
          return "This public URL port does not match the configured Secluso listen port.";
        }
      }
      const hostValue = url.hostname;
      if (hostValue === "localhost" || hostValue === "127.0.0.1" || hostValue === "::1") {
        return "localhost only works on the same machine. Use your public server IP or domain for phone access.";
      }
      const ipv4Match = hostValue.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
      if (ipv4Match) {
        const [a, b] = ipv4Match.slice(1).map(Number);
        if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127) {
          return "This is a private/local IP. Remote access only works if the phone can reach that network or VPN.";
        }
      }
    } catch {
      return null;
    }
    return null;
  }

  async function onTest() {
    errorMsg = "";
    testResult = null;
    testMessage = "";
    testProgressTitle = "";
    testProgressDetail = "";
    activeTestRunId = "";
    const err = validateTarget();
    if (err) { errorMsg = err; return; }

    testing = true;
    testProgressTitle = "Connecting via SSH";
    try {
      await testServerSsh(buildTarget(), buildRuntimePlan(), buildCredentialsServerUrl() || undefined);
      testResult = "ok";
      testMessage = "Preflight OK. SSH, sudo, OS, port, network, and compatibility checks passed.";
      testProgressTitle = "Preflight complete";
      testProgressDetail = "";
      // If they logged in with a key, surface the offer to lock the server to keys only the first time we confirm SSH works.
      if (authMode !== "password") {
        maybePromptDisablePasswordAuth();
      }
    } catch (e: any) {
      testResult = "error";
      testMessage = e?.toString() ?? "SSH test failed.";
      if (!testProgressTitle) testProgressTitle = "Preflight failed";
      if (!testProgressDetail) testProgressDetail = testMessage;
    } finally {
      testing = false;
      activeTestRunId = "";
    }
  }

  async function refreshPasswordAuthState(): Promise<boolean | null> {
    const err = validateTarget();
    if (err) { passwordAuthMessage = err; return null; }
    checkingPasswordAuth = true;
    passwordAuthMessage = "";
    try {
      const enabled = await checkSshPasswordAuth(buildTarget());
      passwordAuthEnabled = enabled;
      passwordAuthMessage = enabled
        ? "Password authentication is currently allowed on this server."
        : "Password authentication is already disabled. Only key-based logins are accepted.";
      return enabled;
    } catch (e: any) {
      passwordAuthEnabled = null;
      passwordAuthMessage = e?.toString() ?? "Could not check SSH password authentication.";
      return null;
    } finally {
      checkingPasswordAuth = false;
    }
  }

  async function runDisablePasswordAuth(): Promise<boolean> {
    disablingPasswordAuth = true;
    try {
      await disableSshPasswordAuth(buildTarget());
      passwordAuthEnabled = false;
      passwordAuthMessage = "Password authentication is now disabled on this server.";
      return true;
    } catch (e: any) {
      passwordAuthMessage = e?.toString() ?? "Failed to disable SSH password authentication.";
      return false;
    } finally {
      disablingPasswordAuth = false;
    }
  }

  async function onCheckPasswordAuth() {
    await refreshPasswordAuthState();
  }

  async function onDisablePasswordAuth() {
    // Always confirm current state before acting so we never reload sshd when the change is already in place.
    const state = await refreshPasswordAuthState();
    if (state === null) return;
    if (state === false) return;
    await runDisablePasswordAuth();
  }

  async function maybePromptDisablePasswordAuth() {
    // Only auto-prompt when the user is already logging in with a key.
    // which proves at least one working key is in authorized_keys
    if (authMode === "password") return;
    if (disablePrompt === "ask" || disablePrompt === "running") return;
    if (disablePromptOutcome === "dismissed" || disablePromptOutcome === "ok") return;
    const state = await refreshPasswordAuthState();
    if (state !== true) return;
    disablePrompt = "ask";
  }

  async function onConfirmDisablePrompt() {
    disablePrompt = "running";
    disablePromptError = "";
    const ok = await runDisablePasswordAuth();
    disablePrompt = "done";
    disablePromptOutcome = ok ? "ok" : "error";
    if (!ok) disablePromptError = passwordAuthMessage;
  }

  function onDismissDisablePrompt() {
    disablePrompt = null;
    if (disablePromptOutcome !== "ok") {
      disablePromptOutcome = "dismissed";
    }
  }

  function validateForKeyGen(): string | null {
    if (!host.trim()) return "Server host/IP is required.";
    if (port < 1 || port > 65535) return "Port must be between 1 and 65535.";
    if (!user.trim()) return "Username is required.";
    if (!hostKeyProof) return "Fetch the SSH host fingerprint before generating a key.";
    if (!hostKeyConfirmed) return "Verify the SSH host fingerprint before generating a key.";
    if (!password) return "Enter your current password so the new public key can be installed.";
    if (!useSameForSudo && !sudoPassword) return "Enter sudo password or toggle same-as-login.";
    return null;
  }

  function onGenerateSshKey() {
    keyGenMessage = "";
    keyGenResult = null;
    keyGenPromptError = "";
    keyGenPassphrase = "";
    keyGenPassphraseConfirm = "";
    const err = validateForKeyGen();
    if (err) {
      keyGenResult = "error";
      keyGenMessage = err;
      return;
    }
    keyGenPromptOpen = true;
  }

  function onCancelKeyGenPrompt() {
    keyGenPromptOpen = false;
    keyGenPassphrase = "";
    keyGenPassphraseConfirm = "";
    keyGenPromptError = "";
  }

  async function onConfirmKeyGenPrompt() {
    if (keyGenPassphrase || keyGenPassphraseConfirm) {
      if (keyGenPassphrase !== keyGenPassphraseConfirm) {
        keyGenPromptError = "Passphrases do not match.";
        return;
      }
      if (keyGenPassphrase.length < 4) {
        keyGenPromptError = "Passphrase must be at least 4 characters, or leave it blank for no passphrase.";
        return;
      }
    }
    const passphrase = keyGenPassphrase;
    keyGenPromptOpen = false;
    keyGenPromptError = "";
    await runKeyGen(passphrase);
  }

  async function runKeyGen(passphrase: string) {
    let defaultFull = "id_ed25519_secluso";
    let savePath: string | null = null;
    const demoActive = !!(devSettings?.enabled && devSettings?.maskUserPathsWithDemo);

    try {
      const def = await getDefaultSshKeyPath();
      if (demoActive && def.homeDirectory) {
        // skip the save dialog in demo mode so recordings don't expose the user's folder layout.
        const sep = def.homeDirectory.includes("\\") && !def.homeDirectory.includes("/") ? "\\" : "/";
        savePath = `${def.homeDirectory}${sep}Desktop${sep}Demo${sep}${def.defaultFileName}`;
      } else {
        defaultFull = def.defaultFullPath || defaultFull;
      }
    } catch {
      // Fall back to a plain name if we can't resolve the home dir.
    }

    if (!savePath) {
      try {
        const picked = await save({
          title: "Choose where to save the new SSH private key",
          defaultPath: defaultFull
        });
        if (typeof picked === "string" && picked.length > 0) {
          savePath = picked;
        }
      } catch (e: any) {
        keyGenResult = "error";
        keyGenMessage = e?.toString() ?? "Failed to open save dialog.";
        return;
      }
    }

    if (!savePath) return;

    generatingKey = true;
    try {
      const comment = `secluso@${host.trim()}`;
      const gen = await generateSshKeypair(savePath, comment, passphrase || undefined);
      generatedKey = gen;
      // Install the public key using the credentials that are currently in the form.. could be password or an existing key.
      await installSshPublicKey(buildTarget(), gen.publicKey);

      // Flip the form to use the new key
      // Clear  the password so we're not holding it in memory any longer than needed.
      authMode = "keyfile";
      keyPath = gen.privatePath;
      keyPassphrase = passphrase;
      password = "";

      keyGenResult = "ok";
      const fileName = gen.publicPath.split(/[\\/]/).pop();
      keyGenMessage = passphrase
        ? `Generated and installed ${fileName} (encrypted with your passphrase). Switched to key-based login.`
        : `Generated and installed ${fileName}. Switched to key-based login.`;
    } catch (e: any) {
      keyGenResult = "error";
      keyGenMessage = e?.toString() ?? "Failed to generate SSH key.";
    } finally {
      generatingKey = false;
    }
  }

  $: showGenerateKeyButton = authMode === "password";

  async function onProvision() {
    errorMsg = "";
    const tErr = validateTarget();
    if (tErr) { errorMsg = tErr; return; }
    if (!userCredentialsQrPath.trim()) {
      await pickUserCredentialsQrSave();
    }
    if (!userCredentialsQrPath.trim()) { errorMsg = "Choose where to save the QR code."; return; }

    const serverUrl = buildCredentialsServerUrl();
    if (!serverUrl) { errorMsg = "Server URL is required to generate credentials."; return; }
    if (effectiveAccessMode() === "direct" && serverUrl.toLowerCase().startsWith("https://")) {
      errorMsg = "Direct mode serves Secluso over plain HTTP on the server port. Use Advanced network setup and Existing reverse proxy if your public URL should be HTTPS.";
      return;
    }
    const useDevRepo = devSettings?.enabled && devSettings.binariesSource === "custom";
    if (useDevRepo && !devSettings?.binariesRepo.trim()) {
      errorMsg = "Dev settings repo is required for a custom updater.";
      return;
    }
    if (useDevRepo) {
      const hasKey1 = !!(devSettings?.key1Name.trim() && devSettings?.key1User.trim());
      const hasKey2 = !!(devSettings?.key2Name.trim() && devSettings?.key2User.trim());
      if (!hasKey1 || !hasKey2) {
        errorMsg = "Dev settings keys are required for a custom updater.";
        return;
      }
    }
    provisioning = true;

    const sigKeys =
      useDevRepo
        ? [
            {
              name: devSettings?.key1Name.trim() ?? "",
              githubUser: devSettings?.key1User.trim() ?? ""
            },
            {
              name: devSettings?.key2Name.trim() ?? "",
              githubUser: devSettings?.key2User.trim() ?? ""
            }
          ].filter((k) => k.name && k.githubUser)
        : [];

    const plan: ServerPlan = {
      runtime: buildRuntimePlan(),
      secrets: {
        serviceAccountKeyPath,
        serverUrl,
        userCredentialsQrPath
      },
      sigKeys: sigKeys.length ? sigKeys : undefined,
      binariesRepo: useDevRepo ? devSettings?.binariesRepo.trim() : undefined,
      githubToken: devSettings?.githubToken.trim() ? devSettings?.githubToken.trim() : undefined,
      manifestVersionOverride:
        devSettings?.enabled && devSettings?.manifestVersionOverride.trim()
          ? devSettings.manifestVersionOverride.trim()
          : undefined,
      overwrite: overwriteInstall
    };

    try {
      const { run_id } = await provisionServer(buildTarget(), plan);
      goto(`/status?mode=server&runId=${encodeURIComponent(run_id)}`);
    } catch (e: any) {
      errorMsg = e?.toString() ?? "Server provisioning failed.";
    } finally {
      provisioning = false;
    }
  }

  async function pickUserCredentialsQrSave() {
    // In demo mode, skip the save dialog so recordings don't expose the
    // user's folder layout. Always land in ~/Desktop/Demo, matching the
    // SSH key generation flow.
    const demoActive = !!(devSettings?.enabled && devSettings?.maskUserPathsWithDemo);
    if (demoActive) {
      try {
        const def = await getDefaultSshKeyPath();
        if (def.homeDirectory) {
          const sep = def.homeDirectory.includes("\\") && !def.homeDirectory.includes("/") ? "\\" : "/";
          userCredentialsQrPath = `${def.homeDirectory}${sep}Desktop${sep}Demo${sep}user_credentials_qr.png`;
          return;
        }
      } catch {
        // Fall back to the normal dialog if we can't resolve the home dir.
      }
    }

    try {
      const path = await save({
        title: "Choose where to save the user credentials QR code…",
        defaultPath: "user_credentials_qr.png",
        filters: [{ name: "PNG image", extensions: ["png"] }]
      });
      if (typeof path === "string" && path.length) userCredentialsQrPath = path;
    } catch (e: any) {
      errorMsg = e?.toString() ?? "Failed to open file picker.";
    }
  }

  onMount(() => {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) {
      devSettings = { ...defaultDevSettings };
      return;
    }
    try {
      const parsed = JSON.parse(raw) as Partial<DevSettings>;
      devSettings = { ...defaultDevSettings, ...parsed };
    } catch {
      devSettings = { ...defaultDevSettings };
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

  onMount(async () => {
    unlistenProvision = await listenProvisionEvents((evt) => handleProvisionEvent(evt));
  });

  onDestroy(() => {
    unlistenProvision?.();
  });

  function handleProvisionEvent(evt: ProvisionEvent) {
    if (!testing && !activeTestRunId) return;
    if (!activeTestRunId) activeTestRunId = evt.run_id;
    if (evt.run_id !== activeTestRunId) return;

    if (evt.type === "step_start") {
      testProgressTitle = evt.title;
      testProgressDetail = "";
      return;
    }

    if (evt.type === "step_ok") {
      if (evt.step === "preflight") {
        testProgressTitle = "Preflight complete";
        testProgressDetail = "";
      }
      return;
    }

    if (evt.type === "step_error") {
      testProgressTitle = evt.step === "ssh_test" ? "SSH check failed" : "Preflight failed";
      testProgressDetail = evt.message;
      return;
    }

    if (evt.type === "log") {
      const line = evt.line.trim();
      if (line) testProgressDetail = line;
      return;
    }
  }

  function toggleFirstTime() {
    firstTimeOn = !firstTimeOn;
    localStorage.setItem(FIRST_TIME_KEY, String(firstTimeOn));
  }

  function setHelpRef() {
    try {
      sessionStorage.setItem("secluso-help-ref", window.location.pathname);
    } catch {
      // best effort only
    }
  }

  function isInteractiveTarget(target: EventTarget | null): boolean {
    return target instanceof Element && !!target.closest("a, button, input, label, textarea, select");
  }

  function onToggleCardClick(event: MouseEvent) {
    if (isInteractiveTarget(event.target)) return;
    toggleFirstTime();
  }

  function onToggleKey(event: KeyboardEvent) {
    if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
      event.preventDefault();
      toggleFirstTime();
    }
  }
</script>

<main class="page">
  <div class="backdrop"></div>

  {#if testResult}
    <div class="overlay" role="status" aria-live="polite">
      <div class="modal {testResult}">
        <div class="modal-title">{testResult === "ok" ? "Preflight OK" : "Preflight failed"}</div>
        <div class="modal-body">{maskDemoText(testMessage)}</div>
        <button class="modal-btn" type="button" on:click={() => (testResult = null)}>Dismiss</button>
      </div>
    </div>
  {/if}

  {#if disablePrompt === "ask" || disablePrompt === "running"}
    <div class="overlay" role="dialog" aria-modal="true" aria-labelledby="disable-pw-title">
      <div class="modal">
        <div class="modal-title" id="disable-pw-title">Disable SSH password authentication?</div>
        <div class="modal-body">
          You're logging in with an SSH key, but this server still accepts password logins.
          Disabling password authentication blocks brute-force guessing and is recommended
          when key-based access is working.
        </div>
        <div class="modal-actions">
          <button class="ghost" type="button" on:click={onDismissDisablePrompt} disabled={disablePrompt === "running"}>
            Not now
          </button>
          <button class="primary modal-confirm" type="button" on:click={onConfirmDisablePrompt} disabled={disablePrompt === "running"}>
            {disablePrompt === "running" ? "Disabling…" : "Disable password auth"}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if disablePrompt === "done"}
    <div class="overlay" role="status" aria-live="polite">
      <div class="modal {disablePromptOutcome === "ok" ? "ok" : "error"}">
        <div class="modal-title">
          {disablePromptOutcome === "ok" ? "Password auth disabled" : "Could not disable password auth"}
        </div>
        <div class="modal-body">
          {disablePromptOutcome === "ok"
            ? "Only key-based SSH logins are accepted from now on."
            : maskDemoText(disablePromptError || "The server did not accept the change.")}
        </div>
        <button class="modal-btn" type="button" on:click={() => { disablePrompt = null; }}>Dismiss</button>
      </div>
    </div>
  {/if}

  {#if keyGenPromptOpen}
    <div class="overlay" role="dialog" aria-modal="true" aria-labelledby="keygen-prompt-title">
      <div class="modal">
        <div class="modal-title" id="keygen-prompt-title">Set a passphrase for the new key?</div>
        <div class="modal-body">
          A passphrase protects the private key file on disk — anyone with the file still
          needs the passphrase to use it. Leave both fields blank for an unprotected key.
        </div>
        <label class="field">
          <span>Passphrase</span>
          <input type="password" bind:value={keyGenPassphrase} autocorrect="off" autocapitalize="off" spellcheck="false" placeholder="Leave blank for no passphrase" />
        </label>
        <label class="field">
          <span>Confirm passphrase</span>
          <input type="password" bind:value={keyGenPassphraseConfirm} autocorrect="off" autocapitalize="off" spellcheck="false" />
        </label>
        {#if keyGenPromptError}
          <small class="harden-status warn">{keyGenPromptError}</small>
        {/if}
        <div class="modal-actions">
          <button class="ghost" type="button" on:click={onCancelKeyGenPrompt}>Cancel</button>
          <button class="primary modal-confirm" type="button" on:click={onConfirmKeyGenPrompt}>
            {keyGenPassphrase ? "Generate with passphrase" : "Generate without passphrase"}
          </button>
        </div>
      </div>
    </div>
  {/if}

  {#if keyGenResult}
    <div class="overlay" role="status" aria-live="polite">
      <div class="modal {keyGenResult}">
        <div class="modal-title">
          {keyGenResult === "ok" ? "SSH key ready" : "Key generation failed"}
        </div>
        <div class="modal-body">
          {maskDemoText(keyGenMessage)}
          {#if keyGenResult === "ok" && generatedKey}
            <div class="key-detail">
              <div><span>Private key:</span> <code>{maskDemoText(generatedKey.privatePath)}</code></div>
              <div><span>Fingerprint:</span> <code>{generatedKey.fingerprint}</code></div>
            </div>
          {/if}
        </div>
        <button class="modal-btn" type="button" on:click={() => { keyGenResult = null; }}>Dismiss</button>
      </div>
    </div>
  {/if}

  <section class="frame">
    <div class="toolbar">
      <button class="back" type="button" on:click={goBack}>
        <img src="/deploy-assets/server-back.svg" alt="" />
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

    <div class="step-pill">Step 2</div>

    <div class="hero">
      <div>
        <h1>Provision Server</h1>
        <p>Install Secluso on your Linux server via SSH. Sets up services, packages, and the auto-updater.</p>
      </div>
      <img class="hero-art" src="/deploy-assets/server-hero-exact.svg" alt="" />
    </div>

    <section class="panel">
      <h2>SSH Target</h2>
      <div class="grid">
        <label class="field field-wide">
          <span>Host / IP</span>
          <input placeholder="server.example.com or 203.0.113.45" bind:value={host} autocorrect="off" autocapitalize="off" spellcheck="false" />
        </label>
        <label class="field">
          <span>Port</span>
          <input type="number" min="1" max="65535" bind:value={port} />
        </label>
        <label class="field">
          <span>User</span>
          <input placeholder="root" bind:value={user} autocorrect="off" autocapitalize="off" spellcheck="false" />
        </label>
      </div>

      <div class="verify-card">
        <div class="verify-card-head">
          <div class="verify-card-copy">
            <div class="label">Verify server identity</div>
            <p class="muted">Fetch the SSH fingerprint, compare it with your provider console or a trusted terminal, then confirm it matches before continuing.</p>
          </div>
          <button class="ghost" type="button" on:click={onFetchHostKey} disabled={fetchingHostKey || testing || provisioning}>
            {fetchingHostKey ? "Fetching…" : "Fetch Fingerprint"}
          </button>
        </div>

        {#if hostKeyProof}
          <label class="field">
            <span>SSH fingerprint</span>
            <input readonly value={`${hostKeyProof.algorithm} ${hostKeyProof.sha256}`} />
            <small class="field-help">If you change the host or port, you will need to fetch and verify it again.</small>
          </label>

          <div class="verify-help">
            <div class="verify-help-title">Where to verify it</div>
            <p class="verify-help-copy">Check this fingerprint in your VPS or cloud provider's web console, or from a trusted terminal already logged into the same server.</p>
            {#if hostKeyVerifyCommand(hostKeyProof)}
              <div class="verify-help-command">{hostKeyVerifyCommand(hostKeyProof)}</div>
              <p class="verify-help-copy">This command checks the exact public host key file that matches the <code>{hostKeyProof.algorithm}</code> key shown above.</p>
            {:else}
              <!-- Fallback only for unexpected key types. Don't want to show something invalid. -->
              <p class="verify-help-copy">This server presented the <code>{hostKeyProof.algorithm}</code> key type. Check the matching public host key file in <code>/etc/ssh</code> from a trusted terminal on the server.</p>
            {/if}
            <p class="verify-help-warning">Do not continue if the fingerprint does not match exactly.</p>
          </div>

          <label class="switch-row verify-check">
            <input type="checkbox" bind:checked={hostKeyConfirmed} />
            <span>I verified this fingerprint belongs to this server</span>
          </label>
        {/if}
      </div>

      <div class="label">Authentication</div>
      <div class="pill-row">
        <label class="choice {authMode === 'password' ? 'selected' : ''}">
          <input type="radio" name="auth" value="password" bind:group={authMode} />
          <img src="/deploy-assets/server-auth-password.svg" alt="" />
          <span>Password</span>
        </label>
        <label class="choice {authMode === 'keyfile' ? 'selected' : ''}">
          <input type="radio" name="auth" value="keyfile" bind:group={authMode} />
          <img src="/deploy-assets/server-auth-keyfile.svg" alt="" />
          <span>Key file</span>
        </label>
        <label class="choice {authMode === 'keypaste' ? 'selected' : ''}">
          <input type="radio" name="auth" value="keypaste" bind:group={authMode} />
          <img src="/deploy-assets/server-auth-paste.svg" alt="" />
          <span>Paste key</span>
        </label>
      </div>

      {#if authMode === "password"}
        <label class="field">
          <span>Password</span>
          <input type="password" bind:value={password} autocorrect="off" autocapitalize="off" spellcheck="false" />
        </label>
      {:else if authMode === "keyfile"}
        <label class="field">
          <span>Private key path</span>
          <div class="field-row">
            <input readonly placeholder="Choose private key" value={maskDemoText(keyPath)} />
            <button class="ghost" type="button" on:click={pickKeyFile}>Choose File</button>
          </div>
        </label>
        <label class="field">
          <span>Key passphrase (optional)</span>
          <input type="password" bind:value={keyPassphrase} placeholder="Only needed for encrypted private keys" autocorrect="off" autocapitalize="off" spellcheck="false" />
        </label>
      {:else}
        <label class="field">
          <span>Private key (PEM/OpenSSH)</span>
          <textarea rows="5" bind:value={keyText} placeholder="-----BEGIN OPENSSH PRIVATE KEY----- …" autocapitalize="off" spellcheck="false"></textarea>
        </label>
        <label class="field">
          <span>Key passphrase (optional)</span>
          <input type="password" bind:value={keyPassphrase} placeholder="Only needed for encrypted private keys" autocorrect="off" autocapitalize="off" spellcheck="false" />
        </label>
      {/if}

      {#if showGenerateKeyButton}
        <div class="keygen-row">
          <button class="ghost" type="button" on:click={onGenerateSshKey}
            disabled={generatingKey || testing || provisioning}>
            {generatingKey ? "Generating…" : "Generate SSH key"}
          </button>
          <small class="keygen-help">
            Creates a new Ed25519 key on this computer, installs the public key on the server,
            and switches this form to key-based login. Requires your current password and a
            verified host fingerprint above.
          </small>
        </div>
      {/if}

      <div class="switch-divider">
        <label class="switch-row">
          <input type="checkbox" bind:checked={useSameForSudo} />
          <span>Use same credentials for sudo</span>
        </label>
      </div>

      {#if !useSameForSudo}
        <label class="field">
          <span>Sudo password</span>
          <input type="password" bind:value={sudoPassword} autocorrect="off" autocapitalize="off" spellcheck="false" />
        </label>
      {/if}

    </section>

    <section class="panel">
      <h2>App Access</h2>
      <p class="muted">Simple mode exposes Secluso directly on <code>http://{host || "your-server"}:{directListenPort}</code>. Use Advanced only if you have a reverse proxy or domain.</p>

      <label class="switch-row">
        <input type="checkbox" bind:checked={advancedNetworkMode} />
        <span>Advanced network setup</span>
      </label>

      {#if advancedNetworkMode}
        <div class="pill-row">
          <label class="choice {accessMode === 'direct' ? 'selected' : ''}"><input type="radio" name="access_mode" value="direct" bind:group={accessMode} /><span>Direct IP / Port</span></label>
          <label class="choice {accessMode === 'proxy' ? 'selected' : ''}"><input type="radio" name="access_mode" value="proxy" bind:group={accessMode} /><span>Existing reverse proxy</span></label>
        </div>

        {#if accessMode === "direct"}
          <div class="grid">
            <label class="field">
              <span>Public server address override</span>
              <input placeholder="203.0.113.10 or http://203.0.113.10:9000" bind:value={directPublicAddress} autocorrect="off" autocapitalize="off" spellcheck="false" />
            </label>
            <label class="field">
              <span>Secluso listen port</span>
              <input type="number" min="1" max="65535" bind:value={directListenPort} />
            </label>
          </div>
        {:else}
          <div class="grid">
            <label class="field">
              <span>Public URL from your reverse proxy</span>
              <input placeholder="https://cam.example.com or https://example.com/secluso" bind:value={proxyPublicUrl} autocorrect="off" autocapitalize="off" spellcheck="false" />
            </label>
            <label class="field">
              <span>Local Secluso listen port</span>
              <input type="number" min="1" max="65535" bind:value={proxyListenPort} />
            </label>
          </div>
        {/if}
      {/if}

      {#if firstTimeOn}
        <div class="hint-card">
          <img src="/deploy-assets/server-info.svg" alt="" />
          <span>Most users should leave this off. Simple mode works great on a spare VPS or home server.</span>
        </div>
      {/if}

      {#if effectiveAccessMode() === "direct"}
        <label class="switch-row">
          <input type="checkbox" bind:checked={allowUfwRule} />
          <span>Allow Secluso to add a ufw rule for the server port if the firewall is active</span>
        </label>
      {/if}

      {#if buildCredentialsServerUrl()}
        <label class="field">
          <span>Final app URL</span>
          <input readonly value={buildCredentialsServerUrl()} />
          {#if credentialsUrlWarning(buildCredentialsServerUrl())}
            <small class="warn-text">{credentialsUrlWarning(buildCredentialsServerUrl())}</small>
          {/if}
        </label>
      {/if}

      <div class="action-row">
        <button class="secondary" type="button" on:click={onTest} disabled={testing || provisioning}>
          {testing ? "Preflight…" : "Run Preflight"}
        </button>
        {#if testing && (testProgressTitle || testProgressDetail)}
          <div class="action-status" aria-live="polite">
            {#if testProgressTitle}
              <span class="action-status-title">{testProgressTitle}</span>
            {/if}
            {#if testProgressDetail}
              <span class="action-status-detail">{maskDemoText(testProgressDetail)}</span>
            {/if}
          </div>
        {/if}
      </div>
    </section>

    {#if authMode !== "password"}
      <section class="panel">
        <h2>Server Hardening</h2>
        <p class="muted">
          Disable SSH password authentication on this server so only key-based logins are accepted.
          Recommended once you've confirmed your SSH key works via preflight above.
        </p>
        <div class="harden-actions">
          <button class="ghost" type="button" on:click={onCheckPasswordAuth}
            disabled={checkingPasswordAuth || disablingPasswordAuth || testing || provisioning}>
            {checkingPasswordAuth ? "Checking…" : "Check status"}
          </button>
          <button class="ghost" type="button" on:click={onDisablePasswordAuth}
            disabled={checkingPasswordAuth || disablingPasswordAuth || testing || provisioning || passwordAuthEnabled === false}>
            {disablingPasswordAuth ? "Disabling…" : "Disable password auth"}
          </button>
        </div>
        {#if passwordAuthMessage}
          <small class="harden-status {passwordAuthEnabled === false ? 'ok' : passwordAuthEnabled === true ? 'warn' : ''}">
            {maskDemoText(passwordAuthMessage)}
          </small>
        {/if}
      </section>
    {/if}

    <section class="panel">
      <h2>Files & Secrets</h2>
      {#if !showFcmSection && !serviceAccountKeyPath}
        <div class="fcm-collapsed">
          <p class="hint-text">
            By default, Android phones receive notifications through UnifiedPush. No Google
            account or Firebase project needed, and more privacy preserving. iOS phones use the
            Secluso iOS Notification relay automatically, no setup on your side, and it's designed
            to be more private than FCM. Most people should leave this alone; check the Build Your
            Own guide if you need help setting up a UnifiedPush distributor on your phone.
          </p>
          <button class="ghost" type="button" on:click={() => (showFcmSection = true)}>
            I want to use FCM (optional)
          </button>
        </div>
      {:else}
        <label class="field">
          <span class="field-label">
            Service account key (JSON, optional)
            <a class="help-link" href="/service-account-help">
              <span>Where to get this?</span>
              <img src="/deploy-assets/server-external-link.svg" alt="" />
            </a>
          </span>
          <div class="field-row">
            <input readonly placeholder="Choose service_account_key.json" value={maskDemoText(serviceAccountKeyPath)} />
            <button class="ghost" type="button" on:click={pickServiceAccountKey}>Choose File</button>
            <button class="ghost" type="button" on:click={() => { serviceAccountKeyPath = ""; showFcmSection = false; }}>
              {serviceAccountKeyPath ? "Clear" : "Hide"}
            </button>
          </div>
          <small class="hint-text">
            Only needed if you want FCM notifications on Android. Most setups should skip this and
            use UnifiedPush instead. iOS phones use the Secluso iOS Notification relay either way.
          </small>
        </label>
      {/if}

      <label class="field">
        <span>Save user credentials QR code to</span>
        <div class="field-row">
          <input readonly placeholder="Choose where to save user_credentials_qr.png" value={maskDemoText(userCredentialsQrPath)} />
          <button class="ghost" type="button" on:click={pickUserCredentialsQrSave}>Choose Path</button>
        </div>
      </label>

      <label class="switch-row">
        <input type="checkbox" bind:checked={overwriteInstall} />
        <span>Overwrite existing install</span>
      </label>
    </section>

    {#if errorMsg}
      <div class="alert error">{maskDemoText(errorMsg)}</div>
    {/if}

    <button class="primary" type="button" on:click={onProvision} disabled={provisioning || testing}>
      {provisioning ? "Provisioning…" : "Provision Server"}
      <img src="/deploy-assets/server-button-arrow.svg" alt="" />
    </button>
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    background: #050608;
    color: #f5f7fb;
    font-family: Inter, "Segoe UI", sans-serif;
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
      radial-gradient(780px 420px at 50% 132px, rgba(255, 255, 255, 0.028), transparent 68%),
      linear-gradient(180deg, rgba(5, 6, 8, 0.98), #050608 46%);
  }

  .appbar {
    height: 57px;
    margin-bottom: 32px;
    position: sticky;
    top: 0;
    z-index: 20;
    background: rgba(3, 3, 3, 0.9);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid rgba(255, 255, 255, 0.03);
  }

  .frame {
    position: relative;
    z-index: 1;
    max-width: 528px;
    margin: 0 auto;
    padding: 24px 24px 0;
    box-sizing: border-box;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 18px;
  }

  .back {
    border: none;
    padding: 0;
    background: transparent;
    color: rgba(255, 255, 255, 0.4);
    cursor: pointer;
    font-size: 13px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    line-height: 19.5px;
  }

  .back img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .tips-toggle {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    color: rgba(255, 255, 255, 0.3);
    font-size: 11px;
    line-height: 16.5px;
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

  .switch-row input {
    appearance: none;
    width: 28.8px;
    height: 16.56px;
    margin: 0;
    border-radius: 999px;
    border: 1px solid transparent;
    background: rgba(255, 255, 255, 0.05);
    position: relative;
    flex: 0 0 auto;
  }

  .action-row {
    margin-top: 20px;
    display: flex;
    align-items: flex-start;
    gap: 14px;
  }

  .action-status {
    flex: 1 1 auto;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .action-status-title {
    color: rgba(255, 255, 255, 0.82);
    font-size: 12px;
    line-height: 16px;
    font-weight: 600;
  }

  .action-status-detail {
    color: rgba(255, 255, 255, 0.4);
    font-size: 11px;
    line-height: 15px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .switch-row input::after {
    content: "";
    position: absolute;
    top: 1.08px;
    left: 0;
    width: 14.4px;
    height: 14.4px;
    border-radius: 999px;
    background: #030303;
    transition: transform 120ms ease;
  }

  .switch-row input:checked {
    background: #00bc7d;
  }

  .switch-row input:checked::after {
    transform: translateX(12.5px);
  }

  .step-pill {
    display: inline-flex;
    align-items: center;
    height: 19px;
    padding: 0 8px;
    border-radius: 14px;
    background: rgba(0, 188, 125, 0.1);
    color: #00d492;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 10px;
    font-weight: 600;
    line-height: 15px;
  }

  .hero {
    position: relative;
    min-height: 121px;
    margin-top: 14px;
  }

  h1 {
    margin: 0;
    font-size: 24px;
    line-height: 32px;
    font-weight: 600;
  }

  .hero p {
    margin: 10px 0 0;
    max-width: 512.75px;
    color: rgba(255, 255, 255, 0.4);
    font-size: 14px;
    line-height: 22.75px;
  }

  .hero-art {
    position: absolute;
    top: -12px;
    right: -16px;
    width: 160px;
    height: 160px;
  }

  .panel {
    margin-top: 32px;
    padding: 16px;
    border-radius: 20px;
    border: 1px solid rgba(255, 255, 255, 0.04);
    background: rgba(255, 255, 255, 0.02);
  }

  .help-link {
    color: #4f90ff;
    text-decoration: none;
    font-size: 11px;
    display: inline-flex;
    align-items: center;
    gap: 3px;
    white-space: nowrap;
  }

  .help-link img {
    width: 12px;
    height: 12px;
    display: block;
  }

  h2 {
    margin: 0 0 20px;
    font-size: 13px;
    line-height: 19.5px;
    font-weight: 600;
  }

  .muted {
    margin: 0;
    color: rgba(255, 255, 255, 0.4);
    font-size: 12px;
    line-height: 19.5px;
  }

  code {
    padding: 1px 5px;
    border-radius: 6px;
    background: rgba(255, 255, 255, 0.05);
    color: rgba(255, 255, 255, 0.82);
  }

  .label {
    margin: 24px 0 10px;
    color: rgba(255, 255, 255, 0.4);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 11px;
    line-height: 16.5px;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px;
  }

  .field-wide { grid-column: 1 / -1; }

  .field {
    display: flex;
    flex-direction: column;
    gap: 9px;
    margin-top: 18px;
  }

  .field > span,
  .field-label {
    color: rgba(255, 255, 255, 0.4);
    font-size: 11px;
    line-height: 16.5px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .field-row {
    display: flex;
    gap: 9px;
  }

  input,
  textarea {
    width: 100%;
    min-width: 0;
    padding: 12px;
    border-radius: 16px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(255, 255, 255, 0.03);
    color: rgba(255, 255, 255, 0.9);
    font: inherit;
    box-sizing: border-box;
  }

  input {
    height: 41.5px;
    font-size: 13px;
    line-height: 19.5px;
  }

  textarea {
    min-height: 110px;
    resize: vertical;
  }

  input::placeholder,
  textarea::placeholder {
    color: rgba(255, 255, 255, 0.28);
  }

  .pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
  }

  .choice {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 36px;
    padding: 0 12px;
    border-radius: 16px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(255, 255, 255, 0.03);
    color: rgba(255, 255, 255, 0.5);
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    box-sizing: border-box;
  }

  .choice img {
    width: 14px;
    height: 14px;
    display: block;
  }

  .choice.selected {
    border-color: rgba(0, 188, 125, 0.3);
    background: rgba(0, 188, 125, 0.15);
    color: #00d492;
  }

  .choice input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }

  .switch-divider {
    margin-top: 16px;
    padding-top: 12px;
    border-top: 1px solid rgba(255, 255, 255, 0.04);
  }

  .switch-row {
    display: flex;
    width: 100%;
    min-height: 28px;
    padding-block: 2px;
    align-items: center;
    gap: 12px;
    color: rgba(255, 255, 255, 0.62);
    font-size: 12px;
    line-height: 18px;
    box-sizing: border-box;
  }

  .switch-row span {
    flex: 1 1 auto;
    min-width: 0;
  }

  .panel > .switch-row {
    margin-top: 14px;
  }

  .switch-row + .switch-row {
    margin-top: 14px;
  }

  .verify-card {
    margin-top: 18px;
    padding-top: 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.04);
  }

  .verify-card-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }

  .verify-card-copy {
    flex: 1 1 auto;
    min-width: 0;
  }

  .verify-card-copy .label {
    margin-top: 0;
  }

  .field-help {
    color: rgba(255, 255, 255, 0.4);
    font-size: 11px;
    line-height: 16px;
  }

  .verify-check {
    margin-top: 16px;
  }

  .verify-help {
    margin-top: 14px;
    padding: 12px 14px;
    border-radius: 16px;
    border: 1px solid rgba(79, 144, 255, 0.14);
    background: rgba(79, 144, 255, 0.06);
  }

  .verify-help-title {
    color: rgba(255, 255, 255, 0.86);
    font-size: 12px;
    font-weight: 600;
    line-height: 16px;
  }

  .verify-help-copy {
    margin: 8px 0 0;
    color: rgba(255, 255, 255, 0.58);
    font-size: 12px;
    line-height: 18px;
  }

  .verify-help-command {
    margin-top: 10px;
    padding: 10px 12px;
    border-radius: 12px;
    background: rgba(3, 7, 18, 0.46);
    border: 1px solid rgba(255, 255, 255, 0.06);
    color: rgba(255, 255, 255, 0.88);
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 12px;
    line-height: 17px;
    overflow-x: auto;
  }

  .verify-help-warning {
    margin: 10px 0 0;
    color: #fbbf24;
    font-size: 12px;
    line-height: 18px;
    font-weight: 600;
  }

  .hint-card {
    margin-top: 16px;
    min-height: 65px;
    padding: 14px 12px 12px 38px;
    border-radius: 16px;
    border: 1px solid rgba(0, 188, 125, 0.1);
    background: rgba(0, 188, 125, 0.05);
    color: rgba(255, 255, 255, 0.5);
    font-size: 12px;
    line-height: 19.5px;
    position: relative;
    box-sizing: border-box;
  }

  .hint-card img {
    position: absolute;
    left: 12px;
    top: 14px;
    width: 16px;
    height: 16px;
    display: block;
  }

  .warn-text {
    margin-top: 2px;
    color: #fbbf24;
    font-size: 12px;
  }

  .hint-text {
    margin-top: 4px;
    color: rgba(255, 255, 255, 0.45);
    font-size: 12px;
    line-height: 1.45;
  }

  .fcm-collapsed {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
  }

  .fcm-collapsed .hint-text {
    margin: 0;
  }

  .fcm-collapsed button {
    height: 36px;
    padding: 0 16px;
    border-radius: 16px;
    font-size: 13px;
  }

  button {
    border: 1px solid rgba(255, 255, 255, 0.08);
    background: rgba(255, 255, 255, 0.04);
    color: rgba(255, 255, 255, 0.84);
    cursor: pointer;
    font: inherit;
  }

  .ghost,
  .secondary {
    padding: 0 16px;
    height: 36px;
    border-radius: 16px;
    white-space: nowrap;
    font-size: 12px;
    color: rgba(255, 255, 255, 0.6);
  }

  .field-row .ghost {
    min-width: 100px;
  }

  .secondary {
    margin-top: 16px;
    width: fit-content;
    min-width: 112px;
    max-width: 100%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex: 0 0 auto;
  }

  .primary {
    width: 100%;
    margin-top: 40px;
    height: 45px;
    border-radius: 20px;
    border: none;
    background: #00bc7d;
    color: #fff;
    font-size: 14px;
    font-weight: 500;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
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

  .alert {
    margin-top: 18px;
    padding: 12px 14px;
    border-radius: 14px;
    border: 1px solid rgba(248, 113, 113, 0.24);
    background: rgba(127, 29, 29, 0.25);
    color: #fecaca;
    font-size: 14px;
  }

  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(2, 6, 23, 0.62);
    display: grid;
    place-items: center;
    z-index: 30;
  }

  .modal {
    width: min(420px, 90vw);
    background: #0a0c11;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 18px;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45);
  }

  .modal.ok { border-color: rgba(18, 216, 159, 0.24); }
  .modal.error { border-color: rgba(248, 113, 113, 0.24); }
  .modal-title { font-size: 18px; font-weight: 700; margin-bottom: 6px; }
  .modal-body { color: rgba(255, 255, 255, 0.64); margin-bottom: 14px; }
  .modal-btn { padding: 10px 14px; border-radius: 10px; }

  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
  }

  .modal-confirm {
    width: auto;
    margin-top: 0;
    padding: 0 16px;
    height: 36px;
    border-radius: 12px;
    font-size: 13px;
  }

  .harden-actions {
    margin-top: 12px;
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .harden-status {
    display: block;
    margin-top: 10px;
    font-size: 11px;
    line-height: 16px;
    color: rgba(255, 255, 255, 0.5);
  }

  .harden-status.ok { color: #00d492; }
  .harden-status.warn { color: #fbbf24; }

  .keygen-row {
    margin-top: 18px;
    display: flex;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 12px;
  }

  .keygen-help {
    flex: 1 1 220px;
    min-width: 0;
    color: rgba(255, 255, 255, 0.45);
    font-size: 11px;
    line-height: 16px;
  }

  .key-detail {
    margin-top: 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    font-size: 12px;
    line-height: 17px;
  }

  .key-detail span {
    color: rgba(255, 255, 255, 0.45);
    margin-right: 6px;
  }

  .key-detail code {
    word-break: break-all;
  }

  @media (max-width: 640px) {
    .appbar-inner,
    .frame { padding-inline: 14px; }
    .hero {
      min-height: 0;
      padding-right: 112px;
    }
    .hero-art { width: 112px; height: 112px; top: -2px; right: -6px; }
    .grid { grid-template-columns: 1fr; }
    .verify-card-head { flex-direction: column; }
    .field-row { flex-direction: column; }
    .secondary,
    .field-row .ghost { width: 100%; }
  }
</style>
