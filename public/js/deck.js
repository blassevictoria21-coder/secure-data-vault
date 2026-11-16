const slides = [...document.querySelectorAll(".slide")];
const counter = document.getElementById("counter");
const bar = document.getElementById("bar");
const notes = document.getElementById("notes");
let i = Math.min(Math.max((parseInt(location.hash.slice(1), 10) || 1) - 1, 0), slides.length - 1);

function fit() {
  const s = Math.min(innerWidth / 1600, innerHeight / 900);
  document.documentElement.style.setProperty("--s", String(s));
}
function show(n) {
  i = Math.min(Math.max(n, 0), slides.length - 1);
  slides.forEach((el, k) => el.classList.toggle("active", k === i));
  counter.textContent = `${i + 1} / ${slides.length}`;
  bar.style.transform = `scaleX(${(i + 1) / slides.length})`;
  notes.textContent = slides[i].dataset.notes || "";
  history.replaceState(null, "", `#${i + 1}`);
}

addEventListener("resize", fit);
addEventListener("keydown", (e) => {
  if (e.target.isContentEditable) return;
  if (["ArrowRight", "PageDown", " ", "Enter"].includes(e.key)) { e.preventDefault(); show(i + 1); }
  else if (["ArrowLeft", "PageUp", "Backspace"].includes(e.key)) { e.preventDefault(); show(i - 1); }
  else if (e.key === "Home") show(0);
  else if (e.key === "End") show(slides.length - 1);
  else if (e.key.toLowerCase() === "n") notes.classList.toggle("hidden");
  else if (e.key.toLowerCase() === "f") toggleFs();
});
let touchX = null;
addEventListener("touchstart", (e) => (touchX = e.touches[0].clientX), { passive: true });
addEventListener("touchend", (e) => {
  if (touchX == null) return;
  const dx = e.changedTouches[0].clientX - touchX;
  if (Math.abs(dx) > 40) show(i + (dx < 0 ? 1 : -1));
  touchX = null;
});

function toggleFs() {
  if (document.fullscreenElement) document.exitFullscreen();
  else document.documentElement.requestFullscreen?.();
}
document.getElementById("prev").addEventListener("click", () => show(i - 1));
document.getElementById("next").addEventListener("click", () => show(i + 1));
document.getElementById("toggle-notes").addEventListener("click", () => notes.classList.toggle("hidden"));
document.getElementById("fs").addEventListener("click", toggleFs);
document.getElementById("print").addEventListener("click", () => window.print());

// Slide 5: live salted SHA-256 demo computed with WebCrypto.
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
async function reroll() {
  const pw = new TextEncoder().encode("Summer2026!");
  for (const k of [1, 2]) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    document.getElementById(`s${k}`).textContent = hex(salt);
    document.getElementById(`h${k}`).textContent = hex(await crypto.subtle.digest("SHA-256", new Uint8Array([...salt, ...pw])));
  }
}
document.getElementById("reroll").addEventListener("click", reroll);

fit();
show(i);
reroll();
