/* R2O motion enhancement. Separate from the API, catalog, Telegram and controls. */
(function (win, doc) {
  'use strict';
  if (!win || !doc) return;
  var reduce = win.matchMedia && win.matchMedia('(prefers-reduced-motion: reduce)');
  var mast = doc.getElementById('mast');
  var hero = doc.querySelector('#now .hero');
  if (!hero || !mast) return;

  var raf = 0;
  function position() {
    raf = 0;
    var y = Math.max(0, win.scrollY || win.pageYOffset || 0);
    mast.classList.toggle('r2o-scrolled', y > 24);
    if (reduce && reduce.matches) {
      hero.style.setProperty('--r2o-glow-y', '0px');
      return;
    }
    // Parallax: lava field drifts at ~half the scroll speed (counter-motion), hero itself does not scale.
    var p = Math.max(0, Math.min(1, y / Math.max(280, hero.offsetHeight * .85)));
    hero.style.setProperty('--r2o-glow-y', (p * 42).toFixed(1) + 'px');
  }
  function schedulePosition() {
    if (!raf) raf = win.requestAnimationFrame(position);
  }
  win.addEventListener('scroll', schedulePosition, { passive: true });
  win.addEventListener('resize', schedulePosition, { passive: true });
  if (reduce && reduce.addEventListener) reduce.addEventListener('change', schedulePosition);
  schedulePosition();

  if ((reduce && reduce.matches) || !win.IntersectionObserver) return;
  var revealSelectors = [
    '.sheet-head', '.filter-bar', '#now .search',
    '#families-body .ftag-wrap', '#families-body .family-row',
    '#boxes-body .crate', '#telegram-body > *',
    '#updates-body > .upd-line', '#updates-body > .update-night',
    '#diagnostics-body > *', '.foot-brand', '.foot-legal'
  ].join(',');
  var visited = new WeakSet();
  var io = new win.IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) return;
      var el = entry.target;
      io.unobserve(el);
      // One-shot reveal, keeps content steady on scroll back and on API updates.
      el.setAttribute('data-r2o-reveal', 'shown');
    });
  }, { threshold: .08, rootMargin: '0px 0px -9% 0px' });

  doc.documentElement.classList.add('r2o-reveal-ready');
  function arm(el, nth) {
    if (!el || visited.has(el) || el.hidden || el.closest('[hidden]')) return;
    visited.add(el);
    var r = el.getBoundingClientRect();
    // No flash or sudden hiding if element is already visible to the user.
    if (r.top < win.innerHeight - Math.min(56, win.innerHeight * .06)) {
      el.setAttribute('data-r2o-reveal', 'shown');
      return;
    }
    el.style.setProperty('--r2o-delay', ((nth % 5) * 58) + 'ms');
    el.setAttribute('data-r2o-reveal', 'pending');
    io.observe(el);
  }
  function scan(root) {
    if (!root || root.nodeType !== 1) return;
    var list = [];
    if (root.matches && root.matches(revealSelectors)) list.push(root);
    if (root.querySelectorAll) {
      var desc = root.querySelectorAll(revealSelectors);
      for (var i = 0; i < desc.length; i++) list.push(desc[i]);
    }
    for (var j = 0; j < list.length; j++) arm(list[j], j);
  }
  scan(doc.getElementById('app'));
  // Live catalog nodes are replaced when API data changes. Reveal new below-fold
  // nodes, but don't rerun motion for any existing element or interfere with Flip.
  if (win.MutationObserver) {
    var pending = [];
    var scheduled = false;
    var mo = new win.MutationObserver(function (records) {
      records.forEach(function (record) {
        record.addedNodes.forEach(function (node) {
          if (node.nodeType === 1 && !node.closest('dialog')) pending.push(node);
        });
      });
      if (scheduled || !pending.length) return;
      scheduled = true;
      win.requestAnimationFrame(function () {
        scheduled = false;
        var batch = pending.splice(0);
        for (var k = 0; k < batch.length; k++) {
          if (batch[k].isConnected) scan(batch[k]);
        }
      });
    });
    mo.observe(doc.getElementById('app'), { childList: true, subtree: true });
  }
})(window, document);
