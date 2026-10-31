# conflux: branches and releases

These hold for every change, by anyone, and the maintenance skill
(`.claude/skills/conflux-maintenance`) follows them too. docs/testing.md, "Branches", has the
why.

- **Branch from `dev`.** A feature or maintenance branch is cut from an up-to-date `dev`
  (`git switch dev && git pull --ff-only origin dev`), never from `version3` and never from
  `main`, which exists on the remote and is not used.
- **Open the pull request against `dev`**, naming the base: `gh pr create --base dev`.
  `version3` is the default branch, so a pull request that names none lands on `version3`, and
  `branch-flow` fails it there.
- **Merge into `dev` only when CI is green.** CI on a pull request into `dev` embeds anchor's
  dev build, `dev-latest`, so the two dev branches are tested together. The merge publishes
  conflux's own dev build: the pre-release `dev-latest`, which the next merge into `dev`
  replaces and which nothing installs unless asked for it by name.
- **Never open or merge a pull request into `version3`.** `version3` takes `dev` and nothing
  else, by a pull request the owner opens; that merge is the release (`VERSION`'s tag and
  `latest`, with anchor's `latest` embedded), and `release.yml` then merges `version3` back into
  `dev`.
- **`dev` stays ahead of `version3`.** Nothing is pushed to `version3` directly. A `branch-flow`
  failure saying `dev` is behind `version3` means the last back-merge did not land: merge
  `version3` into `dev` by pull request.
- **`dev` is the branch, `dev-latest` the pre-release**, here and in anchor. Name the branch in
  full where a command could take either: `origin/dev`, `refs/heads/dev`.
