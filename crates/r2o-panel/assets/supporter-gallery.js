import { supporters } from "./supporters.js";
import { art, artTime, playArt } from "./supporter-art.js";

const mark = '<svg viewBox="0 0 40 40" aria-hidden="true"><use href="#r2o-mark"/><use class="brand-flow" href="#r2o-loop"/></svg>';
const arrow = '<svg viewBox="0 0 24 24" aria-hidden="true"><use href="#i-arrow"/></svg>';
const entryTime = performance.timeOrigin;
let view;
let entryButton;
let goingBack = false;
let styleReady;

function loadStyle() {
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = "/assets/supporter-gallery.css";
  return new Promise((resolve, reject) => {
    link.onload = resolve;
    link.onerror = () => {
      link.remove();
      reject(new Error("Стили галереи недоступны"));
    };
    document.head.append(link);
  });
}

function goBack() {
  if (goingBack) return;
  goingBack = true;
  history.back();
}

function show(id) {
  history.pushState({ ...history.state, r2oGallery: { entryTime, id } }, "");
  sync();
}

function createView() {
  const root = document.createElement("div");
  root.innerHTML = `
    <dialog class="supporter-overlay" id="supporter-gallery" aria-labelledby="supporter-title">
      <div class="supporter-wrap">
        <header class="supporter-bar">
          <div class="supporter-wordmark">${mark}<span>r2o</span></div>
          <p lang="en">R2O — The People Behind the Project</p>
          <button class="supporter-back" type="button">${arrow} К панели</button>
        </header>
        <div class="supporter-intro">
          <div>
            <p class="supporter-kicker" lang="en">Community / Supporters</p>
            <h1 id="supporter-title" tabindex="-1">
              <span>За каждым маршрутом</span> <span>стоят люди.</span>
            </h1>
          </div>
          <p>Тем, кто поддерживает развитие R2O. Спасибо, что помогаете проекту двигаться дальше.</p>
        </div>
        <ul class="supporter-exhibits" aria-label="Участники"></ul>
        <footer class="supporter-footer">
          <div class="supporter-finale" aria-hidden="true">${mark}<canvas data-art-height="178" hidden></canvas></div>
          <p>Каждый вклад — часть истории R2O.</p>
        </footer>
      </div>
    </dialog>
    <dialog class="supporter-overlay supporter-detail" id="supporter-detail" aria-labelledby="supporter-detail-name">
      <div class="supporter-wrap">
        <header class="supporter-bar">
          <div class="supporter-wordmark">${mark}<span>r2o</span></div>
          <button class="supporter-back" type="button">${arrow} К галерее</button>
        </header>
        <div class="supporter-detail-layout">
          <div class="supporter-art" aria-hidden="true"><canvas></canvas></div>
          <div class="supporter-detail-copy">
            <img class="supporter-avatar" alt="" hidden>
            <h2 id="supporter-detail-name" tabindex="-1"></h2>
            <p class="supporter-description"></p>
          </div>
        </div>
      </div>
    </dialog>`;
  const [gallery, detail] = root.children;
  const list = gallery.querySelector(".supporter-exhibits");
  const styles = getComputedStyle(document.documentElement);
  const palette = Object.fromEntries(Object.entries({
    ice: "--acc", teal: "--acc-3", warm: "--amber", ink: "--ink", deep: "--surface-3",
  }).map(([name, token]) => [name, styles.getPropertyValue(token).trim()]));
  const entries = new Map();
  const scenes = [];
  for (const person of supporters) {
    const item = document.createElement("li");
    item.innerHTML = `
      <button type="button" class="supporter-exhibit" aria-haspopup="dialog" aria-controls="supporter-detail">
        <span class="supporter-art" aria-hidden="true"><canvas></canvas></span>
        <span class="supporter-plaque">
          <span class="supporter-caption">
            <span class="supporter-name" dir="auto"></span>
            <span class="supporter-note"></span>
          </span>
          <span class="supporter-arrow" aria-hidden="true">${arrow}</span>
        </span>
      </button>`;
    const button = item.firstElementChild;
    button.dataset.animation = person.animationType;
    button.querySelector(".supporter-name").textContent = person.name;
    button.querySelector(".supporter-note").textContent = person.description;
    button.addEventListener("click", () => show(person.id));
    const canvas = item.querySelector("canvas");
    const draw = art[person.animationType](person.animationConfig, palette);
    scenes.push([canvas, draw]);
    entries.set(person.id, { person, button, canvas, draw });
    list.append(item);
  }
  const final = gallery.querySelector(".supporter-finale");
  const finalCanvas = final.querySelector("canvas");
  if (finalCanvas.getContext("2d")) {
    final.querySelector("svg").setAttribute("hidden", "");
    finalCanvas.hidden = false;
    scenes.push([finalCanvas, art.finale(finalCanvas, document.getElementById("r2o-loop"), palette)]);
  }
  for (const dialog of [gallery, detail]) {
    dialog.querySelector(".supporter-back").addEventListener("click", goBack);
    dialog.addEventListener("cancel", event => {
      event.preventDefault();
      goBack();
    });
  }
  document.body.append(root);
  return { root, gallery, detail, entries, scenes, selection: null, stop: null };
}

function closeView(current) {
  current.detail.close();
  current.gallery.close();
  const opener = entryButton?.getClientRects().length ? entryButton : [...document.querySelectorAll(".brand, .mast-brand")].find(button => button.getClientRects().length);
  opener?.focus({ preventScroll: true });
  const transitions = [current.gallery, current.detail].flatMap(dialog => dialog.getAnimations());
  Promise.allSettled(transitions.map(animation => animation.finished)).then(() => {
    if (!current.gallery.open) {
      current.root.remove();
      if (document.activeElement === document.body) opener?.focus({ preventScroll: true });
      if (view === current) view = null;
    }
  });
}

function showDetail(current, entry) {
  const { detail } = current;
  const { person, button, canvas, draw } = entry;
  const target = detail.querySelector("canvas");
  const title = detail.querySelector("h2");
  title.textContent = person.name;
  title.dir = "auto";
  detail.querySelector(".supporter-description").textContent = person.description;
  const avatar = detail.querySelector(".supporter-avatar");
  avatar.hidden = !person.avatar;
  if (person.avatar) avatar.src = person.avatar;
  else avatar.removeAttribute("src");

  const from = canvas.getBoundingClientRect();
  detail.showModal();
  detail.scrollTop = 0;
  title.focus({ preventScroll: true });
  current.stop = playArt(detail, [[target, draw, artTime(canvas)]]);
  current.selection = button;
  if (!matchMedia("(prefers-reduced-motion: reduce)").matches && from.bottom > 0 && from.top < innerHeight) {
    const to = target.getBoundingClientRect();
    const scale = Math.min(from.width / to.width, from.height / to.height);
    const x = from.left + (from.width - to.width) / 2 - to.left;
    const y = from.top + (from.height - to.height) / 2 - to.top;
    target.animate([
      { transform: `translate(${x}px, ${y}px) scale(${scale})` },
      { transform: "none" },
    ], { duration: 490, easing: "cubic-bezier(.2,.7,.3,1)" });
  }
}

function sync() {
  goingBack = false;
  const state = history.state?.r2oGallery;
  if (state?.entryTime !== entryTime) {
    if (view?.gallery.open) {
      view.stop?.();
      view.stop = null;
      view.selection = null;
      closeView(view);
    }
    return;
  }
  view ??= createView();
  const { gallery, detail, entries, scenes } = view;
  if (!gallery.open) {
    gallery.showModal();
    gallery.scrollTop = 0;
    gallery.querySelector("h1").focus({ preventScroll: true });
  }

  view.stop?.();
  const entry = entries.get(state.id);
  if (entry) showDetail(view, entry);
  else {
    if (detail.open) {
      detail.close();
      view.selection?.focus({ preventScroll: true });
      view.selection = null;
    }
    view.stop = playArt(gallery, scenes);
  }
}

window.addEventListener("popstate", sync);

export async function openGallery(button) {
  styleReady ??= loadStyle().catch(error => { styleReady = null; throw error; });
  await styleReady;
  if (view?.gallery.open) return;
  entryButton = button;
  show(null);
}
