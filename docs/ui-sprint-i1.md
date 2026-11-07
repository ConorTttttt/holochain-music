# UI Sprint I1 — Semantic foundations (initial slice)

Status: proposed PR, **not merged**, 2026-11-07. Base: `feat/v1-app-integration`.

## What changed

- Add named dark/light semantic appearance roles to the existing local UI stylesheet while retaining legacy `--bg`, `--panel` and other aliases. Existing palette values remain **prototypes, not a final brand decision**.
- Introduce pill and circular target-size tokens, apply to existing navigation, actions, fields, search and transport controls, leaving track rows/cards/panels rectangular.
- Give form and button controls a separate, higher-visibility border role rather than depending on decorative separators.
- **Tester-requested:** Add an explicit accessible Appearance select (System / Light / Dark) to the topbar, with safe browser-local persistence. The System option uses the OS media query; manual overrides work regardless of OS setting. This is only a visual preference and does not alter the user identity or audio engine.
- Introduce a font-family token using the existing system fonts. **Plus Jakarta Sans is selected, but not yet bundled or integrated.**
- Add dependency-free static contract tests. These are guards for token declarations and shapes, **not** browser or WCAG passes.

## Architecture and compatibility

The current music app is a Python service with a loopback HTML/CSS/vanilla-JavaScript UI, not a React/Electron shell. I1 intentionally changes **only UI CSS and UI contract tests**. No audio, signed-grant, network, key, payment, storage, or renderer-to-native boundary is modified.

The base is the shared `feat/v1-app-integration` line. The Windows branch (`feat/v1-windows-port`) is a separate descendant, and artist PRs #23/#24 are another chain. Do not auto-merge/rebase them without conflict assessment, preserving any local/uncommitted Windows RC3 patches.

## Validation / definition of done

- Run `python -m unittest discover -s tests -p 'test_v1_ui_design.py' -v` (structural guards only).
- Run `python -m unittest discover -s tests -p 'test_v1_app_server.py' -v` to check the local token-protected API. This fixture normally uses `/tmp` to keep Holochain keystore paths short. If `/tmp` is quota-limited, check `df -h /tmp "$HOME"`, `df -i /tmp "$HOME"` and optionally `quota -s`, then use a **short path on a writable filesystem with free space**, e.g. `mkdir -p "$HOME/hm-tmp" && HOLOCHAIN_MUSIC_TEST_TMPDIR="$HOME/hm-tmp" python -m unittest discover -s tests -p 'test_v1_app_server.py' -v`. Avoid deleting arbitrary system `/tmp` files. This override affects **only the test fixture** and does not change application data or keys.
- Run existing full Python/Rust/JS and integration tests in the proper environment before merge.
- Inspect System/Light/Dark controls, preference persistence after browser refresh, zoom, keyboard focus, player controls and forms on Linux/Windows. Manual theme colour testing is still required.
- Check that resizes/seek/track-switches remain smooth, particularly Windows physical speaker quality.
- Obtain actual colour approval before final contrast audit / screenshot baseline.
- Package the chosen font legally and locally; don't fetch a third-party web font at runtime.

## Deferred follow-on work

Full reusable JS component wrappers, Phosphor icons, validated system font assets, improved responsive layout, status/Activity Centre and audio/session adapters belong in following I1/I2 increments.

References: [Step 20 selected plan](https://app.notion.com/p/411b6c6d5c0481cabf4ceb5393cde213), [Component design](https://app.notion.com/p/411b6c6d5c0481d3b60ded42796ff0cb), [Colour research (undecided)](https://app.notion.com/p/410b6c6d5c048193842ae8ad89c9f0f4).
