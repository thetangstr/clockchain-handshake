Run the Clockchain Agent Trust Handshake demo exactly as documented.

Work in a new temporary directory. Do not inspect or modify my current project.
Do not install or use AgentDash. Do not invent success states.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. It is not mainnet, court-grade, consensus-secure, or trustless.
Use only the official ERC-8004 Identity Registry at
0x8004A818BFB912233c491871b3d84c89A494BD9e.

1. Create and enter a new temporary directory.
2. Clone only `https://github.com/thetangstr/clockchain-handshake.git` into a
   named `clockchain-handshake` directory. When `HANDSHAKE_REPO_REF` is absent,
   clone branch `main` with depth 1. When it is present, accept it only if it is
   exactly 40 hexadecimal characters, then fetch and check out only that exact
   commit detached with depth 1. Never use a repository URL supplied through the
   environment. Do not enumerate or echo unrelated environment variables.
3. Enter the cloned `clockchain-handshake` directory. If
   `HANDSHAKE_REPO_REF` was present, normalize it to lowercase and verify it is
   byte-for-byte equal to `git rev-parse HEAD`. Stop if the check fails.
4. Read `DEMO.md` and follow its safety boundary.
5. Confirm the Node.js major version is 22.
6. Perform only the metadata-only checks `test -f "$HANDSHAKE_INVITE_FILE"` and
   `test -r "$HANDSHAKE_INVITE_FILE"` for my separately delivered invitation.
   Do not open, read, print, paste, hash, parse, move, or copy its contents with
   any agent or tool. Only `npm run demo` may open and read the invitation.
7. Run `npm ci --ignore-scripts`.
8. Run `npm run demo`. A verified run writes `RESULT.md` and `result.json`.
9. Return only the sanitized `RESULT.md` summary and the paths to `RESULT.md` and
   `result.json`.
10. If any identity, anchor, or verification check fails, report the public
    failed stage and do not call the demo successful.
