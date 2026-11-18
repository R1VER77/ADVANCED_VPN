# cypherpunk_vpn desktop application

Linux frontend in Vue 3, TypeScript and Tauri 2. The ordinary-user app talks to
`org.cypherpunk_vpn.Controller1` on the system bus. The root controller owns
networking, enrollment and hardware access. This implementation remains under
validation; the owner/provider setup branch and real participant sessions are incomplete.

## Build and run

Use Node 22.23.5 and the committed npm and Cargo lockfiles. Linux native builds
require the Tauri WebKitGTK 4.1 development dependencies.

```sh
npm ci --ignore-scripts
npm run build
npx tauri build --no-bundle
```

Install the matching verified controller package separately. Run the desktop app
as your ordinary desktop user. A browser preview cannot access the system broker
and correctly shows status as unavailable. Production never falls back to a mock.

For the separate simulated prototype:

```sh
npm run dev:demo
npm run build:demo
```

`demo.html`, `DemoApp.vue` and `controller/mock.ts` are excluded from the production
entry. The simulated PIN dialog belongs only to that demo. Production accepts no
PIN, passphrase, cloud token, shell command or arbitrary privileged file path.

## Current behavior

- Controller-derived setup checklist with one current prompt, checked progress,
  explicit repair review, cancellation and bounded signed-bundle import.
- Fresh protection evidence and an explicit applications/whole-device scope.
  Unavailable or contradictory evidence displays status unknown.
- Caller-bound, expiring, one-use plans. Native administrator authentication repeats
  the stored summary, effects and digest outside the WebView. Hardware PINs remain
  in the trusted native/device prompt. Unlocking retains traffic protection.
- Offline Natural Earth map, original project logo and locally bundled assets.
  Existing signed profiles do not contain geographic coordinates; production leaves
  the map unlocated rather than inventing provider or region labels.
- IVPN-inspired split layout, Wayqo violet palette, keyboard focus and reduced-motion
  support. No IVPN source or artwork was imported. See asset provenance files.

The repository LICENSE governs this component. The original standalone prototype
was preserved before import; `PROTOTYPE_ORIGIN.json` records its source hashes.

## Validation status

Production and demo web builds and native Rust checking/Clippy have passed locally.
These checks do not qualify native installation, D-Bus/Polkit integration, a complete
owner setup or usability with five new participants. The production npm dependency
audit reported zero findings. The build dependency tree still contains the unpatched
picomatch advisory GHSA-fc5q-39xc-vjpf; six high results include its dependent packages.
It remains an open build-toolchain finding, not a waived or fixed issue.

See `CONTROLLER_CONTRACT.md` and the main implementation progress document.
