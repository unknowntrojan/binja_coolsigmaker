# binja_coolsigmaker

We all know signature scanning can be extremely useful. Sadly, the two public offerings for Binja are either very slow, or crash extremely often.

This is why I wrote this plugin. It's a signature scanning and creating plugin for x86 (more archs are planned!), written in Rust. It's extremely fast, supports multiple signature styles, and works like a charm.

It supports 3 styles of signatures. Or 4, if you want to be specific.

To create a signature, select the instruction you want the signature to point to, then go to `Plugins->CSM - Create Signature`.

The signature is checked for uniqueness within all executable segments of the binary. `.data` is not considered, so make sure your signature scanning implementation also ignores non-code sections.

To find a signature, copy the signature to your clipboard in the format you selected in the configuration, and go to `Plugins->CSM - Find Signature`. All occurrences will be in your log.

These are the settings:

![settings](https://i.imgur.com/BK4Q0E5.png)

This is how it looks to create a signature, then scan for it:

![pattern creation and scanning](https://i.imgur.com/qkjdU2M.png)

## How to install

1. Download the platform-appropiate binary from release section
2. Place the binary in your Binary Ninja installation's plugin folder

Once GitHub Actions are set up and a loader plugin has been written, you will be able to install the plugin via the official plugin manager.

## Compiling yourself

This project requires the nightly channel of Rust.

Check the Cargo.toml file and adjust the `binaryninja` dependency so it points to whatever Binja update channel you want to compile for. __!MAKE SURE!__ Cargo caught your change of branch. It sometimes doesn't realize you changed it. Delete `Cargo.lock` and/or run `cargo clean`. Otherwise, it'll keep using whatever version was selected when you built or rust-analyzer ran.

The Stable tag needs to be updated periodically, there is no "newest-stable" tag.
