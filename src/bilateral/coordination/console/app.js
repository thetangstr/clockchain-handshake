const output = document.querySelector("#projection");
const status = document.querySelector("#status");
async function refresh() { try { const response = await fetch("/v1/console/session", { cache: "no-store" }); if (!response.ok) throw new Error("unavailable"); const projection = await response.json(); status.textContent = `Phase: ${projection.phase.value}`; output.textContent = JSON.stringify(projection, null, 2); } catch { status.textContent = "Projection unavailable."; output.textContent = ""; } }
refresh(); setInterval(refresh, 3000);
