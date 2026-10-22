# Changelog

## [0.5.0](https://github.com/aaronburt/netscan/compare/v0.4.2...v0.5.0) (2026-10-22)


### Features

* **dashboard:** show how fresh the slower probes are ([addc967](https://github.com/aaronburt/netscan/commit/addc967ede868c810acbf55ec1f5f533da6b2522))
* probe less often in normal mode (8 to about 3 probes a second) ([dde40d5](https://github.com/aaronburt/netscan/commit/dde40d516791f8b307ed2b8895c2122bfcfc0883))
* probe less often in normal mode, confirm failures straight away ([09ca612](https://github.com/aaronburt/netscan/commit/09ca612ac2efe88ab30e4670d117fcf34670e868))


### Bug Fixes

* code review cleanup (shutdown hang, scheduler stall, detector and dashboard accuracy) ([0589362](https://github.com/aaronburt/netscan/commit/05893620e22684d73c2f409ea21429b08b8ae7b9))
* **dashboard:** show real probe data, escape backend text, report write errors ([c10ffde](https://github.com/aaronburt/netscan/commit/c10ffdeb1459560a120fcc47b67d9507c5fdf090))
* **detector:** close the open event as interrupted when the app exits ([6d347a3](https://github.com/aaronburt/netscan/commit/6d347a33ff2c3d982ad05881cab97d63f0426fa3))
* **detector:** count every target in a layer, record one-probe blips, copy events ([d33b9d0](https://github.com/aaronburt/netscan/commit/d33b9d0336cf852dffd70b4f235ae0c1a70bd94a))
* **probe:** unique target ids for any number of targets, IPv6 DNS resolvers ([93b0d01](https://github.com/aaronburt/netscan/commit/93b0d015ee8228289c3371d7f5a84fde6e48f8dc))
* **scheduler:** keep probing after fast mode ends and don't treat pauses as sleeps ([59d42d6](https://github.com/aaronburt/netscan/commit/59d42d699d8e510f5be7c07a98f0ac4fc6182cac))
* **server:** stop the live stream from freezing, make pause/resume POST-only ([675c889](https://github.com/aaronburt/netscan/commit/675c8896b48ec3e704d0c60101a07b1e4402daae))
* stop shutdown and update-restart from hanging, keep event ids unique ([894e489](https://github.com/aaronburt/netscan/commit/894e48970ab07d78e2fc905efe044c3face91ed1))
* **updater:** refuse updates that have no checksum ([0c5e643](https://github.com/aaronburt/netscan/commit/0c5e643aca1c99181420de0cd677f9e0e9c8b983))
