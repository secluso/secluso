// SPDX-License-Identifier: GPL-3.0-or-later
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type SshAuth =
  | { kind: "password"; password: string }
  | { kind: "keyfile"; path: string; passphrase?: string }
  | { kind: "keytext"; text: string; passphrase?: string };

export interface SudoSpec {
  mode: "same" | "password";
  password?: string;
}

export interface SshTarget {
  host: string;
  port: number;
  user: string;
  auth: SshAuth;
  sudo: SudoSpec;
  expectedHostKey?: HostKeyProof;
}

export interface SshHostKeyTarget {
  host: string;
  port: number;
}

// Mirrors provision_server/types.rs::HostKeyProof
export interface HostKeyProof {
  algorithm: string;
  sha256: string;
}

export interface ServerRuntimePlan {
  exposureMode: "direct" | "proxy";
  bindAddress: string;
  listenPort: number;
  allowUfwRule?: boolean;
}

export interface ServerPlan {
  runtime: ServerRuntimePlan;
  secrets?: { serviceAccountKeyPath: string; serverUrl: string; userCredentialsQrPath: string };
  overwrite?: boolean;
  sigKeys?: { name: string; githubUser: string; fingerprint?: string }[];
  binariesRepo?: string;
  githubToken?: string;
  manifestVersionOverride?: string;
}

export interface JobStart {
  run_id: string;
}

export type ProvisionEvent =
  | { type: "step_start"; run_id: string; step: string; title: string }
  | { type: "step_ok"; run_id: string; step: string }
  | { type: "step_error"; run_id: string; step: string; message: string }
  | { type: "log"; run_id: string; level: "info" | "warn" | "error"; step?: string; line: string }
  | { type: "done"; run_id: string; ok: boolean };

export interface PrepareImageRequest {
  qrOutputPath: string;
  imageOutputPath: string;
  customWicPath?: string;
  binariesRepo?: string;
  sigKeys?: { name: string; githubUser: string; fingerprint?: string }[];
  githubToken?: string;
}

export interface DeployVersionStatus {
  currentVersion: string;
  latestVersion: string;
  releaseTag: string;
  outdated: boolean;
}

export async function testServerSsh(target: SshTarget, runtime?: ServerRuntimePlan, serverUrl?: string): Promise<void> {
  await invoke("test_server_ssh", { target, runtime, serverUrl });
}

export async function fetchServerHostKey(target: SshHostKeyTarget): Promise<HostKeyProof> {
  return invoke("fetch_server_host_key", { target });
}

export async function provisionServer(
  target: SshTarget,
  plan: ServerPlan
): Promise<JobStart> {
  return invoke("provision_server", { target, plan });
}

export async function prepareImage(req: PrepareImageRequest): Promise<JobStart> {
  return invoke("prepare_image", { req });
}

export async function openExternalUrl(url: string): Promise<void> {
  await invoke("open_external_url", { url });
}

export async function getDeployVersionStatus(): Promise<DeployVersionStatus> {
  return invoke("get_deploy_version_status");
}

export async function listenProvisionEvents(
  handler: (event: ProvisionEvent) => void
): Promise<UnlistenFn> {
  return listen<ProvisionEvent>("provision:event", (evt) => handler(evt.payload));
}
