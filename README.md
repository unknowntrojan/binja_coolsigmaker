# binja_coolsigmaker

We all know signature scanning can be extremely useful. Sadly, the two public offerings for Binja are either very slow, or crash extremely often.

This is why I wrote this plugin. It's a signature scanning and creating plugin written in Rust. It's extremely fast, supports multiple signature styles, and works like a charm.

It supports 3 styles of signatures. Or 4, if you want to be specific.

These are the settings:

![settings](https://i.imgur.com/BK4Q0E5.png)

This is how it looks to create a signature, then scan for it:

![pattern creation and scanning](https://i.imgur.com/qkjdU2M.png)

## How to install

1. Download the platform-appropiate binary from release section
2. Place the binary in your Binary Ninja installation's plugin folder

Once GitHub Actions are set up and a loader plugin has been written, you will be able to install the plugin via the official plugin manager.
