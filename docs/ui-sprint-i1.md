# UI Sprint I1 — Semantic foundations (initial slice)

Status: proposed PR, **not merged**, 2026-11-07. Base: `feat/v1-app-integration`.

## What changed

- Add named dark/light semantic appearance roles to the existing local UI stylesheet while retaining legacy `--bg`, `--panel` and other aliases. Existing palette values remain **prototypes, not a final brand decision**.
- Introduce pill and circular target-size tokens, apply to existing navigation, actions, fields, search and transport controls, leaving track rows/cards/panels rectangular.
- Give form and button controls a separate, higher-visibility border role rather than depending on decorative separators.
- Introduce a font-family token using the existing system fonts. **Plus Jakarta Sans is selected, but not yet bundled or integrated.**
- Add dependency-free static contract tests. These are guards for token declarations and shapes, **not** browser or WCAG passes.

## Architecture and compatibility

The current music app is a Python service with a loopback HTML/CSS/vanilla-JavaScript UI, not a React/Electron shell. I1 intentionally changes **only UI CSS and UI contract tests**. No audio, signed-grant, network, key, payment, storage, or renderer-to-native boundary is modified.

The base is the shared `feat/v1-app-integration` line. The Windows branch (`feat/v1-windows-port`) is a separate descendant, and artist PRs #23/#24 are another chain. Do not auto-merge/rebase them without conflict assessment, preserving any local/uncommitted Windows RC3 patches.

## Validation / definition of done

- Run `python -m unittest discover -s tests -p 'test_v1_ui_design.py' -v` (structural guards only).
- Run existing full Python/Rust/JS and integration tests in the proper environment before merge.
- Inspect dark/light screens, zoom, keyboard focus, player controls and forms on Linux/Windows.
- Check that resizes/seek/track-switches remain smooth, particularly Windows physical speaker quality.
- Obtain actual colour approval before final contrast audit / screenshot baseline.
- Package the chosen font legally and locally; don't fetch a third-party web font at runtime.

## Deferred follow-on work

Full reusable JS component wrappers, Phosphor icons, validated system font assets, improved responsive layout, status/Activity Centre and audio/session adapters belong in following I1/I2 increments.

References: [Step 20 selected plan](https://app.notion.com/p/411b6c6d5c0481cabf4ceb5393cde213), [Component design](https://app.notion.com/p/411b6c6d5c0481d3b60ded42796ff0cb), [Colour research (undecided)](https://app.notion.com/p/410b6c6d5c048193842ae8ad89c9f0f4).
