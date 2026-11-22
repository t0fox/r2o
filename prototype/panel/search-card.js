(() => {
  'use strict';
  if (new URLSearchParams(location.search).get('search-ui') !== '1') return;
  document.documentElement.setAttribute('data-search-concept','');
  const reduce = matchMedia('(prefers-reduced-motion: reduce)');
  const glyphs = {
    queued: 'M12 6v6l3 2',
    running: 'M4 12h3l2-4 3 8 3-7 2 3h3',
    saved: 'm6.5 12 3.5 3.5 7.5-8',
    partial: 'M7 12h10',
    failed: 'm8 8 8 8m0-8-8 8'
  };

  function mount(row) {
    const {visual, phase, clock} = row.__parts;
    visual.insertAdjacentHTML('afterbegin', `<svg class="status-mark" viewBox="0 0 48 48" aria-hidden="true">
      <circle class="status-mark-rail" cx="24" cy="24" r="19" pathLength="100"/>
      <circle class="status-mark-arc" cx="24" cy="24" r="19" pathLength="100"/>
      <path class="status-mark-glyph" pathLength="1" transform="translate(12 12)"/>
    </svg>`);
    const chip = document.createElement('div');
    chip.className = 'search-call';
    chip.innerHTML = '<span class="search-call-fill" aria-hidden="true"></span><span class="search-call-icon" aria-hidden="true"></span>';
    phase.before(chip);
    chip.append(phase, clock);
    row.classList.add('search-concept');
    return {
      chip,
      icon: chip.querySelector('.search-call-icon'),
      glyph: visual.querySelector('.status-mark-glyph')
    };
  }

  window.R2oSearchConcept = (row, search) => {
    const ui = row.__searchConcept || (row.__searchConcept = mount(row));
    const track = row.__parts.track;
    const steps = track.querySelectorAll('.track-step');
    const at = track.hidden ? undefined : track.__r2oAt;
    const state = search.outcome === 'saved' ? 'saved' : search.outcome === 'partial' ? 'partial' :
      search.outcome === 'closed' ? 'failed' : at === 0 ? 'queued' : 'running';
    const progress = state === 'saved' ? 1 : Number.isInteger(at) ? at / steps.length : 0;
    const key = state + ':' + at;
    if (ui.key === key) return;
    const changed = ui.key !== undefined;
    ui.key = key;
    row.dataset.callState = state;
    row.style.setProperty('--call-progress', progress);
    ui.glyph.setAttribute('d', glyphs[state]);

    const icon = steps[at]?.querySelector('svg');
    if (icon && (state === 'queued' || state === 'running')) {
      ui.icon.replaceChildren(icon.cloneNode(true));
    } else {
      const badge = document.createElementNS(ui.glyph.namespaceURI, 'svg');
      badge.setAttribute('viewBox', '0 0 24 24');
      const path = ui.glyph.cloneNode();
      path.removeAttribute('transform');
      path.removeAttribute('class');
      badge.append(path);
      ui.icon.replaceChildren(badge);
    }
    ui.icon.getAnimations().forEach(animation => animation.cancel());
    ui.glyph.getAnimations().forEach(animation => animation.cancel());
    ui.feedback?.cancel();
    if (reduce.matches) return;
    ui.icon.animate([{opacity: .2, transform: 'translateY(3px)'}, {opacity: 1, transform: 'translateY(0)'}],
      {duration: 220, easing: 'ease-out'});
    if (state === 'failed' && changed) {
      ui.feedback = ui.chip.animate([0, -2, 2, -1, 0].map(x => ({transform: `translateX(${x}px)`})), {duration: 200});
    }
    if (state !== 'queued' && state !== 'running') {
      ui.glyph.animate([{strokeDashoffset: 1}, {strokeDashoffset: 0}], {duration: 240, easing: 'ease-out'});
    }
  };
})();
