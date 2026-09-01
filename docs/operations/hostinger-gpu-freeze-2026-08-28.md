# Hostinger GPU worker freeze — 2026-08-28

## Frozen state

- Freeze checkpoint: `2026-08-28T12:05:24Z`.
- Hostinger instance: `706`, `hostinger-hch-worker-01`, Ollama template.
- Worker node: `hostinger-hch-worker-01`.
- Repository branch: `MacBook-Pro-de-Paulo`.
- Repository base HEAD: `ac556b698ff1c14c904857f78383650d75b3c040`.
- Active runtime at freeze: `/usr/local/libexec/hch-editorial-runtime-ac556b698ff1`.
- Preserved rollback runtime: `/usr/local/libexec/hch-editorial-runtime-5d4f6b1c86c7`.
- Applied manifest sequence: `5`.
- Applied manifest hash: `9baff244f66727518f03b5a5b5a23a6ccfbf27803a8758af38ffc45f9588a8b9`.
- Worker service: `inactive/dead` after a clean stop in drain.
- Ollama service: `inactive/dead` after a clean stop.
- GPU compute processes after stop: none.
- Last verified worker state before stop: `draining`, requested/granted capacity `0/0`, active assignments `0`, claims disabled, current batch `null`.
- Worker service restart count before stop: `0`.

The Hostinger GPU product does not offer a pause/stop operation that preserves the instance. The hPanel exposes only reboot and permanent destroy. The instance was therefore not destroyed. Credits continue to be consumed while it exists, even with both services stopped. See [Hostinger GPU billing and credits](https://www.hostinger.com/support/how-to-manage-billing-and-credits-for-your-hostinger-gpu-instance/).

## Durable external backup

The recovery archive is stored on `hubtech-vps` at:

```text
/opt/hubtech/backups/hch-worker/hostinger-hch-worker-01/20260828T120524Z/hostinger-hch-worker-01-freeze.tar.gz
```

- Size: `43M`.
- SHA-256: `f978193a508b123184ba4a053c7c00cc9edd12553104f62c68a055399c8902e6`.
- Ownership/mode: root-only backup directory and archive mode `0600`.
- Archive integrity: `tar -tzf` passed after transfer.
- Contents: worker state and identity, configuration and trust root, systemd unit/drop-ins, current and rollback runtimes, pinned Node runtime and worker control CLI.
- Ollama model blobs were not copied; the applied model/digest remains declared in the signed runtime state and can be pulled again.

The four tracked worktree changes were also preserved separately as:

```text
/opt/hubtech/backups/hch-worker/hostinger-hch-worker-01/20260828T120524Z/WORKTREE.patch
```

- Patch SHA-256: `08381c6a1a0d7b4f8b815ef0e2e57d7d0e5c190300e5dfc0714438c59cd9e089`.
- At the initial freeze, `.codex-gpu-benchmark.mjs` was not in this patch. It
  was subsequently used as the off-queue diagnostic harness and included in
  the device branch by the user's explicit instruction to persist all work.

Before any restore, verify the archive without extracting it:

```bash
ssh hubtech-vps 'sudo -n sha256sum /opt/hubtech/backups/hch-worker/hostinger-hch-worker-01/20260828T120524Z/hostinger-hch-worker-01-freeze.tar.gz'
```

## Preserved local worktree

No commit or push was made during this freeze. Preserve these tracked modifications:

```text
ops/linux/editorial-worker/lib/generator.mjs
ops/linux/editorial-worker/test/adaptive-runtime.test.mjs
scripts/check-hostinger-gpu-worker.sh
scripts/test/check-hostinger-gpu-worker.test.sh
```

At this initial checkpoint, `.codex-gpu-benchmark.mjs` remained outside the
commit and release archive. The later continuation checkpoint below supersedes
that handling for the Git device branch; it is still not part of an installed
worker runtime unless a future release explicitly includes it.

Implemented but not published:

- classify only Ollama `done_reason=length` as a safe output-budget exhaustion;
- retry that condition once without raising signed `num_predict` and without reusing partial content;
- keep incomplete protocol, HTTP, stall and cancellation failures fail-fast;
- use a regeneration operation when no valid previous candidate exists;
- validate the Hostinger dashboard through a loopback SSH tunnel instead of requiring a public control endpoint;
- allow nonnegative global generating workload while still requiring this node to be fully drained.

Final targeted generator suite passed `48/48`. The complete test matrix must be rerun because the user requested interruption while the final Hostinger preflight suite was executing. The interrupted suite left no test process running.

## Resume existing instance

If instance `706` still exists, do not redeploy and do not restore the archive. Resume in this order:

1. Confirm SSH resolves to the expected Hostinger instance and verify both services remain inactive.
2. Start Ollama only:

   ```bash
   ssh hostinger-gpu 'sudo -n systemctl start ollama.service'
   ```

3. Verify `127.0.0.1:11434`, the canonical model name/digest and GPU visibility.
4. Start the worker while preserving drain:

   ```bash
   ssh hostinger-gpu 'sudo -n systemctl start hch-editorial-worker.service'
   ```

   Do not use `hch-editorial-workerctl start`; that command restores the last nonzero capacity and opens claims.
5. Recreate the Mac tunnel if needed:

   ```bash
   ssh -N hostinger-worker-dashboard
   ```

   Open `http://127.0.0.1:4320/`.
6. Require two successful heartbeats about 60 seconds apart with capacity zero, claims disabled, GPU available, zero active assignments and restart count still zero.
7. Rerun `npm test`, `npm run test:windows`, `git diff --check` and the live tunnel preflight.
8. Review the complete diff, commit only the four tracked files above plus this checkpoint when appropriate, and push without force only to `MacBook-Pro-de-Paulo`.
9. Build the next runtime strictly from `git archive <commit>`, install it immutably and repeat the controlled single-assignment canary before widening capacity.

## Restore after permanent destroy

Destroy is irreversible and was not performed during this freeze. If a later explicit decision destroys the instance:

1. Deploy a new Ollama GPU instance; its IP, SSH port and exposed-service mappings may change.
2. Update the local SSH aliases only after verifying the new host key out of band.
3. Verify the external archive SHA-256 before extraction.
4. Reinstall required system account/directories, then restore files with original numeric ownership and modes.
5. Re-pull the exact signed Ollama model digest.
6. Revalidate the NVIDIA device minor and regenerate the restricted `DeviceAllow` drop-in; never assume the previous `/dev/nvidia4` mapping.
7. Run bootstrap and validation with capacity zero, then start the service through systemd in drain.
8. Require two successful heartbeats and a controlled canary before claims are widened.

## Resume verification — 2026-08-28

The existing instance was resumed from this checkpoint without restoring or
changing its identity:

- Ollama restarted with listener only on `127.0.0.1:11434`;
- canonical `qwen2.5:1.5b-instruct` model/digest verified;
- bootstrap explicitly renewed with capacity zero and manifest sequence `5`;
- worker started through `systemctl`, not `workerctl start`;
- post-start heartbeats succeeded at `15:11:25.306Z` and `15:12:25.080Z`;
- both heartbeats kept capacity zero, claims disabled and GPU available;
- service restart count remained zero;
- the local dashboard tunnel was restored at `127.0.0.1:4320`;
- the Hostinger public mapping on port `20002` remained unreachable from outside;
- Linux suite passed `92/92`;
- dashboard suite passed `30/30`;
- Windows suite passed `37`, skipped `14`, failed `0`;
- hardened Hostinger preflight suite passed `24/24`;
- live Hostinger preflight ended with `remote_preflight=pass`,
  `tunnel_dashboard=verified` and `preflight=pass`.

The worker remained drained throughout this resume verification. No assignment
was claimed before the candidate runtime deployment and controlled canary.

## Continuation freeze — 2026-08-28T15:51:42Z

Execution was interrupted again for continuation from another notebook. The
durable Git state and the remote runtime state at this boundary are:

- device branch before the final checkpoint commit:
  `MacBook-Pro-de-Paulo@79e0e71a3b53fde1005a9caeb6be4fd2dacd4bc7`;
- the same commit was already present at
  `origin/MacBook-Pro-de-Paulo` without force;
- active runtime symlink:
  `/usr/local/libexec/hch-editorial-runtime-79e0e71a3b53`;
- preserved older runtimes:
  `/usr/local/libexec/hch-editorial-runtime-ac556b698ff1` and
  `/usr/local/libexec/hch-editorial-runtime-5d4f6b1c86c7`;
- `hch-editorial-worker.service=inactive` and `ollama.service=inactive`;
- no `worker.mjs`, benchmark, `llama-server` or `ollama serve` process remained;
- control stayed fail-closed: `acceptingClaims=false`, `drainRequested=true`,
  `requestedCapacity=0`, `updatedBy=pause`;
- the service was stopped only after there were no active assignments.

The immutable candidate was built from commit `79e0e71` and installed after
the full deterministic matrix passed. Its single controlled real canary
claimed only assignment `44f433dc-76ea-43b0-8696-99742016bf28`, then claims
were closed immediately. The assignment failed with
`generator-output-incomplete`; no second assignment was claimed. The worker
ended with two historical jobs claimed and two failed, zero running jobs and
`currentBatch=null`. This is a failed canary, not an operational promotion.

The Ollama evidence for that failure was HTTP 200, approximately 754 generated
tokens and `truncated=0`. A simple non-streaming probe completed with
`done=true` and `done_reason=stop`, so the failure is specific to the longer
streaming path. Ollama version `0.33.1` was installed.

The final source checkpoint adds fail-closed diagnostic categories without
accepting any new terminal condition:

- `generator-output-terminal-missing`;
- `generator-output-terminal-reason-missing`;
- `generator-output-terminal-reason-unknown`;
- `generator-output-empty`;
- data after the unique terminal event is rejected as an invalid response;
- the only retryable terminal remains the exact `done_reason=length`, once,
  with the same signed output budget.

The targeted adaptive runtime suite passed `50/50` for this diagnostic patch.
An off-queue synthetic `1x1` run against a temporary copy of the patched
runtime did not mutate the queue and left claims closed. It completed the
Ollama protocol but failed editorial validation with
`LEN-001`, `LEN-002` and `LEN-004` in `5.991s`. This distinguishes a valid
terminal/JSON response from an editorial success: the configured
`qwen2.5:1.5b-instruct` remains unproven for the signed long-form contract.

Models present at the checkpoint were `qwen2.5:1.5b-instruct` and
`llama3.2:3b`. The GPU was an NVIDIA RTX PRO 6000 Blackwell Server Edition with
97249 MiB reported memory. Ollama was configured with
`OLLAMA_NUM_PARALLEL=64`; the loaded 1.5B model therefore reserved a 524288
token aggregate context. Do not extrapolate this setting to a larger model:
the next notebook must benchmark success rate and valid drafts per minute with
physical VRAM bounds before changing the signed RuntimeProfile.

### Exact continuation gates

1. Fetch `MacBook-Pro-de-Paulo` and confirm the checkpoint commit is the remote
   head; never resume from `main` implicitly.
2. Confirm both remote services remain inactive and the worker control file
   still has claims disabled, drain enabled and requested capacity zero.
3. Start Ollama, verify loopback-only binding, version, GPU and exact model
   digest. Start the worker through `systemctl` only; never use
   `hch-editorial-workerctl start` during recovery.
4. Require bootstrap/validation and two healthy zero-capacity heartbeats before
   any off-queue benchmark.
5. Rerun the complete Linux, dashboard, Windows and Hostinger preflight matrix
   for the final checkpoint commit.
6. Use the persisted `.codex-gpu-benchmark.mjs` only off-queue and initially as
   `concurrency=1`, `samples=1`. It is diagnostic evidence, not a canary.
7. Require at least two sequential valid off-queue drafts before another
   single-assignment canary. A canary must finish as `pending-review`; HTTP 200,
   a terminal `stop` or GPU utilization alone is insufficient.
8. Keep claims closed after any failure and never widen capacity without that
   real canary proof.
