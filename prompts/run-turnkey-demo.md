Run the Clockchain Agent Trust Handshake demo exactly as documented.

Work in a new temporary directory. Do not inspect or modify my current project.
Do not install or use AgentDash. Do not invent success states.

This is an Ethereum Sepolia and Clockchain® single-validator testnet exercise.
No money moves. It is not mainnet, court-grade, consensus-secure, or trustless.
Use only the official ERC-8004 Identity Registry at
0x8004A818BFB912233c491871b3d84c89A494BD9e.

1. Create and enter a new temporary directory.
2. Use the process environment values `HANDSHAKE_REPO_URL` and
   `HANDSHAKE_REPO_REF` when they are set. Otherwise use
   `https://github.com/thetangstr/clockchain-handshake.git` and `main`.
   Clone that repository and ref with depth 1. Do not enumerate or echo unrelated
   environment variables.
3. Read `DEMO.md` and follow its safety boundary.
4. Confirm the Node.js major version is 22.
5. Confirm `HANDSHAKE_INVITE_FILE` points to my separately delivered invitation
   file. Never print, paste, copy, or open that file in chat; pass its path to the
   runner.
6. Run `npm ci --ignore-scripts`.
7. Run `npm run demo`. A verified run writes `RESULT.md` and `result.json`.
8. Return only the sanitized `RESULT.md` summary and the paths to `RESULT.md` and
   `result.json`.
9. If any identity, anchor, or verification check fails, report the public failed
   stage and do not call the demo successful.
