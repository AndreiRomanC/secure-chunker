# Secure Chunker

A small Rust desktop GUI for packing a folder into a compressed, chunked, authenticated-encrypted archive and restoring it later.

## Pipeline
Pack: folder -> TAR stream -> Zstandard compression -> fixed-size chunks -> AES-256-GCM per chunk.
Unpack reverses the pipeline and verifies every encrypted chunk before restoration.

## Build
Install current stable Rust, then:

    cargo run --release

## Notes
- The encrypted chunks are opaque binary data, but this project does **not** attempt to conceal that encryption is being used. Security comes from standard authenticated encryption, not from hiding the format.
- A `manifest.json` records ordering, salt, and non-secret metadata. Keep all parts together.
- Passwords are expanded to a 256-bit key with Argon2.
- This is a functional prototype. Before using it for irreplaceable data, add automated round-trip tests, interruption recovery, streaming without a temporary archive, and independent security review.

## Build a Windows .exe with GitHub Actions
This repository includes `.github/workflows/windows-build.yml`.

1. Create a GitHub repository and upload/push this project to it.
2. Open the repository on GitHub and go to **Actions**.
3. Open **Build Windows EXE**.
4. Click **Run workflow** (or simply push to `main`/`master`).
5. When the workflow finishes, open the completed run.
6. Download the artifact named **secure_chunker-windows-x64**.
7. Inside the downloaded artifact you will find `secure_chunker.exe`.

The executable is built natively on GitHub's Windows runner in release mode.
