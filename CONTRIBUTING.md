# Contributing Guidelines

This repository is an academic secure-programming case study. Keep changes easy to review, and do not publish local secrets, generated keys, or machine-specific configuration.

---

## Keeping Your Branch Up-to-Date

To stay current with `main`:

  ```bash
  git fetch origin
  git checkout -b feature/your-feature-name
  git merge origin/main
  # Resolve any conflicts
  git push origin feature/your-feature-name
  ```

---

## Commit Messages

- Use commit messages that say what changed in plain language.

---

## Pull Request Guidelines

- Open a pull request from your feature branch to `main`.
- Keep PRs small enough to review confidently.
- Include a clear title and short description of what changed and why.
- Tag a reviewer when your PR is ready for review.

## Public Repository Rules

- Do not commit `.env` files, private keys, certificates, generated binaries, local database material, or test media containing personal information.
- Keep example configuration values clearly non-production.
- Document security limitations honestly instead of presenting the prototype as production-ready.
