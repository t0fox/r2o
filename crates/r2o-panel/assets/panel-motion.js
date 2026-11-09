/* R2O motion: только рабочая хореография интерфейса.
   Тень операционной панели при прокрутке. Без декоративных эффектов. */
(function (win, doc) {
  "use strict";
  if (!win || !doc) return;
  var mast = doc.getElementById("mast");
  if (!mast) return;
  var raf = 0;
  function update() {
    raf = 0;
    mast.classList.toggle("is-scrolled", (win.scrollY || win.pageYOffset || 0) > 12);
  }
  function schedule() {
    if (!raf) raf = win.requestAnimationFrame(update);
  }
  win.addEventListener("scroll", schedule, { passive: true });
  win.addEventListener("resize", schedule, { passive: true });
  schedule();
})(window, document);
