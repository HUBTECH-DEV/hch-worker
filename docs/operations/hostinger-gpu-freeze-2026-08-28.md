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
- The unrelated `.codex-gpu-benchmark.mjs` is not in this patch.

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

The unrelated untracked file `.codex-gpu-benchmark.mjs` must remain outside any commit and release archive.

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
