const short = value => value ? `${value.slice(0, 8)}…${value.slice(-6)}` : "—";

async function connect() {
  const network = document.querySelector("#network");
  try {
    const response = await fetch("/api/config", { cache: "no-store" });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "Gateway unavailable");
    network.classList.add("online");
    network.querySelector("span").textContent = "Local chain online";
    document.querySelector("#chain-id").textContent = short(body.chain_id);
    document.querySelector("#chain-head").textContent = Number(body.head.height).toLocaleString();
    document.querySelector("#account").textContent = short(body.account);
  } catch (error) {
    network.classList.remove("online");
    network.querySelector("span").textContent = error instanceof Error ? error.message : "Offline";
  }
}

connect();
