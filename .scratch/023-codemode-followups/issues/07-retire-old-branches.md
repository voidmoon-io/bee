# Retire the pre-port branches and local backups

Status: ready-for-human

Do after 01 merges.

- Local branches `fix/f001-reload-transactional` and `feat/codemode-batch-nesting` hold
  the pre-port line (base checkpoint `fd2fd91`, which diverged from `main` 92 commits
  back). Everything in them that was meant to ship is in #49. Its version numbers
  (store v8, journal v4) never shipped. Delete the branches, or archive them as tags.
- `/tmp/bee-scratch-backup-1793498479` holds local copies of 13 `.scratch` files that
  differ from the versions `main` tracks (`tigerstyle-*`, `artex-harness`). These copies
  were moved aside before the merge attempt and not restored. Decide whether those
  edits matter before `/tmp` is cleared.
- Untracked `.scratch/artex-harness/`, `.scratch/tigerstyle-hardening/PR.md` and
  `VULN-FINDINGS-current.*` were restored in place and are still untracked.
