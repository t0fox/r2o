/* Локальная история отключена по умолчанию и никуда не отправляется.
   Формат и функции 1:1 с диагностикой D2O; процессы адаптированы под R2O. */
(function (root) {
  "use strict";
  var SVG = "http://www.w3.org/2000/svg";
  var PRIMARY = "r2o-controller";
  var metrics = [
    { key: "rss", label: "RSS", color: "rss" },
    { key: "rss_anon", label: "RssAnon", color: "rss_anon" },
    { key: "vm_data", label: "VmData", color: "vm_data" },
    { key: "anonymous", label: "Anonymous", color: "anonymous" },
    { key: "private_dirty", label: "Private_Dirty", color: "private_dirty" },
    { key: "catalog", label: "Каталог", color: "catalog" },
    { key: "http", label: "HTTP", color: "http" },
    { key: "snapshot", label: "Снимки", color: "snapshot" },
    { key: "tracked_tcp", label: "TCP", color: "tracked_tcp" },
    { key: "tracked_quic", label: "QUIC", color: "tracked_quic" },
    { key: "tracked_tls", label: "TLS", color: "tracked_tls" }
  ];
  var reasons = {
    cpu: "CPU", memory: "память", conntrack: "conntrack", slots: "слоты",
    "resource-data-unavailable": "ресурсные данные недоступны",
    "no-current-resource-limit": "текущих ограничений нет"
  };
  function list(value) { return Array.isArray(value) ? value : []; }
  function number(value) { return typeof value === "number" && isFinite(value) ? value : null; }
  function pretty(value) { return value === null ? "—" : String(value); }
  var fractional = new Intl.NumberFormat("ru-RU", { minimumFractionDigits: 1, maximumFractionDigits: 1 });
  var integral = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 0 });
  function formatBytes(bytes) {
    if (number(bytes) === null || bytes < 0) return "—";
    if (bytes >= 1048576) return fractional.format(bytes / 1048576) + "\u00a0МиБ";
    if (bytes >= 1024) return fractional.format(bytes / 1024) + "\u00a0КиБ";
    return integral.format(bytes) + "\u00a0Б";
  }
  function formatKib(kib) { return number(kib) === null ? "—" : formatBytes(kib * 1024); }
  function formatDeltaBytes(bytes) {
    if (number(bytes) === null) return "—";
    return (bytes > 0 ? "+" : bytes < 0 ? "−" : "") + formatBytes(Math.abs(bytes));
  }
  function kibBytes(kib) { return number(kib) === null ? null : kib * 1024; }
  function formatAge(ms) {
    if (number(ms) === null || ms < 0) return "—";
    if (ms < 1000) return Math.round(ms) + " мс";
    if (ms < 60000) return Math.floor(ms / 1000) + " с";
    var seconds = Math.floor(ms / 1000) % 60;
    return Math.floor(ms / 60000) + "\u00a0мин" + (seconds ? " " + seconds + "\u00a0с" : "");
  }
  function intervalText(ms, axisUnit) {
    var interval = number(ms) === null || ms <= 0 ? "Интервал указан в отчёте" :
      ms % 60000 === 0 ? "Снимок раз в " + (ms / 60000) + " мин" :
      ms % 1000 === 0 ? "Снимок раз в " + (ms / 1000) + " с" : "Снимок раз в " + ms + " мс";
    return axisUnit ? interval + " · " + axisUnit : interval;
  }
  function sampleWord(count) { return count % 10 === 1 && count % 100 !== 11 ? "снимке" : "снимках"; }
  function countWithCapacity(count, capacity) {
    return number(capacity) !== null && capacity > 0 ? count + " / " + capacity : String(count);
  }
  function firstDefined(listOfValues) {
    for (var i = 0; i < listOfValues.length; i++) if (number(listOfValues[i]) !== null) return listOfValues[i];
    return null;
  }
  function detailsFor(report) {
    return list(report.memory_details).filter(function (item) { return item && item.name === PRIMARY; })[0] || null;
  }
  function sumGroups(smaps, field) {
    if (!smaps) return null;
    var groups = ["anonymous", "heap", "stack", "other"], total = 0, seen = false;
    groups.forEach(function (group) {
      var value = smaps[group] && number(smaps[group][field]);
      if (value !== null) { total += value; seen = true; }
    });
    return seen ? total : null;
  }
  function sampleTime(sample) {
    var mono = number(sample && sample.mono_ms);
    return mono === null ? number(sample && sample.at) : mono / 1000;
  }
  function memoryField(memory, row, key, legacyIndex) {
    var fields = list(memory && memory.fields);
    if (fields.length) {
      var index = fields.indexOf(key);
      return index < 0 ? null : number(row[index]);
    }
    return number(row[legacyIndex]);
  }
  function memoryBytesField(memory, row, bytesKey, kibKey, legacyIndex) {
    var fields = list(memory && memory.fields);
    if (fields.length) {
      var bytesIndex = fields.indexOf(bytesKey);
      if (bytesIndex >= 0) return number(row[bytesIndex]);
      var kibIndex = fields.indexOf(kibKey);
      return kibIndex < 0 ? null : kibBytes(number(row[kibIndex]));
    }
    return kibBytes(number(row[legacyIndex]));
  }
  function sampleForHistoryRow(report, at, time, domain) {
    var nearest = null, distance = Infinity;
    list(report.samples).forEach(function (sample) {
      var sampleMono = number(sample && sample.mono_ms), candidateAt = number(sample && sample.at);
      var d = domain === "mono" && sampleMono !== null && number(time) !== null ? Math.abs(sampleMono / 1000 - time) :
        number(at) !== null && candidateAt !== null ? Math.abs(candidateAt - at) : Infinity;
      if (d <= 1 && d < distance) { nearest = sample; distance = d; }
    });
    return nearest;
  }
  function generationForSample(report, at, time, domain) {
    var sample = sampleForHistoryRow(report, at, time, domain);
    var proc = sample && list(sample.processes).filter(function (item) { return item && item.name === PRIMARY; })[0];
    return proc && number(proc.pid) !== null ? proc.pid : null;
  }
  function memoryRows(report) {
    var memory = report.memory_history, history = list(memory && memory.samples);
    if (history.length) {
      var base = list(memory.time_base), wallBase = number(base[0]), monoBase = number(base[1]);
      var finalRow = Array.isArray(history[history.length - 1]) ? history[history.length - 1] : [];
      var wallDelta = memoryField(memory, finalRow, "at_delta_s", 0);
      var monoDelta = memoryField(memory, finalRow, "mono_delta_s", 1);
      var finalTime = monoBase !== null && monoDelta !== null ? monoBase + monoDelta : null;
      var finalAt = wallBase !== null && wallDelta !== null ? wallBase + wallDelta : null;
      var source = list(report.samples).find(function (sample) { return sample.at === finalAt; });
      var precise = number(source && source.mono_ms);
      // Старые отчёты R2O хранили миллисекунды в полях, объявленных в секундах.
      var divisor = finalTime !== null && precise !== null
        ? (Math.abs(finalTime - precise) < Math.abs(finalTime * 1000 - precise) ? 1000 : 1)
        : (wallDelta > 0 && monoDelta > wallDelta * 100 ? 1000 : 1);
      return history.map(function (row) {
        if (!Array.isArray(row)) return null;
        var atDelta = memoryField(memory, row, "at_delta_s", 0);
        var monoDelta = memoryField(memory, row, "mono_delta_s", 1);
        var at = wallBase === null || atDelta === null ? null : wallBase + atDelta;
        var timeDomain = monoBase !== null && monoDelta !== null ? "mono" : "wall";
        var time = timeDomain === "mono" ? (monoBase + monoDelta) / divisor : at;
        var rollupIndex = list(memory.fields).length ? list(memory.fields).indexOf("smaps_rollup_kib") : 7;
        var rollup = rollupIndex < 0 || !Array.isArray(row[rollupIndex]) ? [] : row[rollupIndex];
        var epoch = memoryField(memory, row, "d2kc_epoch", -1);
        var result = {
          at: at, time: time, time_domain: timeDomain, generation: epoch,
          rss: kibBytes(memoryField(memory, row, "rss_kib", 2)),
          vm_data: kibBytes(memoryField(memory, row, "vm_data_kib", 3)),
          vm_swap: kibBytes(memoryField(memory, row, "vm_swap_kib", 4)),
          status: memoryField(memory, row, "smaps_rollup_status_code", 5),
          errno: memoryField(memory, row, "smaps_rollup_errno", 6),
          rss_anon: kibBytes(memoryField(memory, row, "rss_anon_kib", 8)),
          catalog: memoryBytesField(memory, row, "catalog_bytes", "catalog_kib", 9),
          http: memoryBytesField(memory, row, "http_bytes", "http_kib", 10),
          snapshot: memoryBytesField(memory, row, "snapshot_bytes", "snapshot_kib", 11),
          tracked_tcp: memoryBytesField(memory, row, "tracked_tcp_bytes", "tracked_tcp_kib", 12),
          tracked_quic: memoryBytesField(memory, row, "tracked_quic_bytes", "tracked_quic_kib", 13),
          tracked_tls: memoryBytesField(memory, row, "tracked_tls_bytes", "tracked_tls_kib", 14),
          tasks: memoryField(memory, row, "tasks", 15), workers_live: memoryField(memory, row, "workers_live", 16),
          workers_result_pending: memoryField(memory, row, "workers_result_pending", 17),
          workers_join_pending: memoryField(memory, row, "workers_join_pending", 18),
          anonymous: kibBytes(number(rollup[2])), private_dirty: kibBytes(number(rollup[3]))
        };
        var sample = sampleForHistoryRow(report, at, time, timeDomain), fields = list(memory.fields);
        if (epoch === null) result.generation = generationForSample(report, at, time, timeDomain);
        if (sample && (!fields.length || fields.indexOf("catalog_bytes") < 0)) result.catalog = number(sample.catalog_bytes) === null ? result.catalog : sample.catalog_bytes;
        if (sample && (!fields.length || fields.indexOf("http_bytes") < 0)) result.http = number(sample.http_bytes) === null ? result.http : sample.http_bytes;
        if (sample && (!fields.length || fields.indexOf("snapshot_bytes") < 0)) result.snapshot = number(sample.snapshot_bytes) === null ? result.snapshot : sample.snapshot_bytes;
        return result;
      }).filter(Boolean);
    }
    var rows = list(report.samples).map(function (sample) {
      var proc = list(sample && sample.processes).filter(function (item) { return item && item.name === PRIMARY; })[0] || {};
      return {
        at: number(sample && sample.at), time: sampleTime(sample), time_domain: number(sample && sample.mono_ms) === null ? "wall" : "mono", generation: number(proc.pid),
        rss: kibBytes(number(proc.rss_kib)), rss_anon: kibBytes(number(proc.anon_kib)),
        vm_data: kibBytes(number(proc.vm_data_kib)), anonymous: null, private_dirty: null,
        catalog: number(sample && sample.catalog_bytes), http: number(sample && sample.http_bytes),
        snapshot: number(sample && sample.snapshot_bytes), tracked_tcp: null, tracked_quic: null, tracked_tls: null,
        status: null, errno: null
      };
    });
    var detail = detailsFor(report), latest = detail && detail.latest;
    if (latest && rows.length) {
      var final = rows[rows.length - 1], rollup = latest.smaps_rollup;
      final.vm_data = firstDefined([latest.vm_data_kib, final.vm_data]);
      if (rollup) {
        final.rss = firstDefined([kibBytes(number(rollup.rss_kib)), final.rss]);
        final.anonymous = kibBytes(number(rollup.anonymous_kib));
        final.private_dirty = kibBytes(number(rollup.private_dirty_kib));
      } else if (latest.smaps) {
        final.anonymous = kibBytes(sumGroups(latest.smaps, "anonymous_kib"));
        final.private_dirty = kibBytes(sumGroups(latest.smaps, "private_dirty_kib"));
      }
      if (latest.smaps_rollup_status === "unavailable") final.status = 1;
      else if (latest.smaps_rollup_status === "parse-error") final.status = 3;
      else if (latest.smaps_rollup_status === "unsupported") final.status = 4;
      final.errno = number(latest.smaps_rollup_errno);
    }
    return rows;
  }
  function rowsInRange(rows, hours, intervalMs) {
    if (!rows.length) return [];
    var timed = rows.filter(function (row) { return number(row.time) !== null; });
    if (!timed.length) return rows.slice(-Math.ceil(hours * 3600000 / (number(intervalMs) || 60000)));
    var last = timed[timed.length - 1].time;
    var start = last - hours * 3600;
    return timed.filter(function (row) { return row.time >= start; });
  }
  function seriesEndpoints(rows, key) {
    var end = null;
    for (var i = rows.length - 1; i >= 0; i--) if (number(rows[i][key]) !== null) { end = rows[i]; break; }
    if (!end) return { first: null, last: null, delta: null };
    if (key === "rss" && number(end.generation) === null) return { first: end, last: end, delta: null };
    var first = null, count = 0;
    for (var j = 0; j < rows.length; j++) {
      if (key === "rss" && end.generation !== null && number(end.generation) !== null && rows[j].generation !== end.generation) continue;
      if (number(rows[j][key]) !== null) { if (!first) first = rows[j]; count++; }
    }
    return { first: first, last: end, delta: count > 1 ? end[key] - first[key] : null };
  }
  function durationText(seconds) {
    if (number(seconds) === null || seconds < 60) return "менее минуты";
    var minutes = Math.floor(seconds / 60), hours = Math.floor(minutes / 60), days = Math.floor(hours / 24);
    if (days) return days + " д " + (hours % 24) + " ч";
    if (hours) return hours + " ч " + (minutes % 60) + " мин";
    return minutes + " мин";
  }
  function rangeText(hours) { return hours === 2 || hours === 24 ? hours + " часа" : hours + " часов"; }
  function coverageText(rows, hours) {
    if (!rows.length) return "Доступно 0 снимков из " + rangeText(hours) + ".";
    var timed = rows.filter(function (row) { return number(row.time) !== null; });
    if (!timed.length) return "Время снимков отсутствует · точек: " + rows.length + ".";
    var span = Math.max(0, timed[timed.length - 1].time - timed[0].time);
    return "Доступно " + durationText(span) + " из " + rangeText(hours) + " · снимков: " + rows.length + ".";
  }
  function svg(doc, name, attrs) {
    var node = doc.createElementNS(SVG, name);
    Object.keys(attrs || {}).forEach(function (key) { node.setAttribute(key, attrs[key]); });
    return node;
  }
  function timeLabel(seconds) {
    if (number(seconds) === null) return "—";
    return new Date(seconds * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  function drawMemory(doc, allRows, hours, intervalMs, size) {
    var chart = doc.getElementById("diagnostic-memory-chart"), empty = doc.getElementById("diagnostic-memory-empty");
    if (!chart || !empty) return { rows: [], delta: null, axisUnit: null };
    var rows = rowsInRange(allRows, hours, intervalMs);
    var options = {}, available = {};
    metrics.forEach(function (metric) {
      var input = doc.querySelector('[data-memory-series="' + metric.key + '"]');
      available[metric.key] = rows.some(function (row) { return number(row[metric.key]) !== null; });
      if (input) {
        input.parentNode.hidden = !available[metric.key];
        options[metric.key] = input.checked;
        var valueNode = input.parentNode.querySelector("small");
        if (!valueNode) { valueNode = doc.createElement("small"); input.parentNode.appendChild(valueNode); }
        var endpoints = seriesEndpoints(rows, metric.key);
        valueNode.textContent = endpoints.last === null ? "—" : formatBytes(endpoints.last[metric.key]) +
          (endpoints.delta === null ? "" : " · " + formatDeltaBytes(endpoints.delta));
      }
    });
    var active = metrics.filter(function (metric) { return available[metric.key] && options[metric.key]; });
    var legend = doc.getElementById("diagnostic-legend");
    legend.replaceChildren(...active.map(function (metric) {
      var item = doc.createElement("li");
      var key = svg(doc, "svg", { width: 16, height: 8, viewBox: "0 0 16 8", "aria-hidden": "true" });
      key.append(svg(doc, "path", { d: "M1 4h14", "class": "diag-line diag-line-" + metric.color }));
      item.append(key, metric.label);
      item.translate = false;
      return item;
    }));
    doc.getElementById("diagnostic-series-options").hidden = !Object.values(available).some(Boolean);
    var all = [];
    active.forEach(function (metric) { rows.forEach(function (row) { if (number(row[metric.key]) !== null) all.push(row[metric.key]); }); });
    chart.replaceChildren();
    chart.dataset.points = String(rows.length);
    chart.setAttribute("aria-label", "Память контроллера, период " + hours + " часа, точек: " + rows.length);
    if (!rows.length || !active.length || !all.length) {
      chart.setAttribute("hidden", "");
      empty.hidden = false;
      empty.textContent = !active.length && rows.length ? "Выберите доступный показатель памяти." : "Для выбранного периода нет доступных снимков памяти.";
      return { rows: rows, delta: null, axisUnit: null };
    }
    chart.removeAttribute("hidden"); empty.hidden = true;
    var width = size.width, height = size.height;
    chart.setAttribute("viewBox", "0 0 " + width + " " + height);
    var left = width < 400 ? 40 : 56, right = width - 10, top = 12, bottom = height - 30;
    var min = Math.min.apply(Math, all), max = Math.max.apply(Math, all);
    var scale = max >= 1048576 ? 1048576 : max >= 1024 ? 1024 : 1;
    var axisUnit = scale === 1048576 ? "МиБ" : scale === 1024 ? "КиБ" : "Б";
    if (min === max) { var pad = Math.max(min * .08, 128); min = Math.max(0, min - pad); max += pad; }
    else { var margin = (max - min) * .08; min = Math.max(0, min - margin); max += margin; }
    for (var tick = 0; tick <= 4; tick++) {
      var y = top + (bottom - top) * tick / 4;
      chart.appendChild(svg(doc, "line", { x1: left, x2: right, y1: y, y2: y, "class": "diag-gridline" }));
      var label = svg(doc, "text", { x: left - 8, y: y + 4, "text-anchor": "end" });
      label.textContent = (scale === 1 ? integral : fractional).format((max - (max - min) * tick / 4) / scale);
      chart.appendChild(label);
    }
    chart.appendChild(svg(doc, "line", { x1: left, x2: right, y1: bottom, y2: bottom, "class": "diag-axis" }));
    var timedRows = rows.filter(function (row) { return number(row.time) !== null; });
    var firstTime = timedRows.length ? timedRows[0].time : null, lastTime = timedRows.length ? timedRows[timedRows.length - 1].time : null;
    function xFor(row, index) {
      if (rows.length === 1) return (left + right) / 2;
      if (number(row.time) !== null && firstTime !== null && lastTime > firstTime) {
        return left + (right - left) * (row.time - firstTime) / (lastTime - firstTime);
      }
      return left + (right - left) * index / (rows.length - 1);
    }
    var xLabelStart = svg(doc, "text", { x: rows.length === 1 ? xFor(rows[0], 0) : left, y: height - 7, "text-anchor": rows.length === 1 ? "middle" : "start" });
    xLabelStart.textContent = timeLabel(rows[0].at);
    chart.appendChild(xLabelStart);
    if (rows.length > 1) {
      var xLabelEnd = svg(doc, "text", { x: right, y: height - 7, "text-anchor": "end" });
      xLabelEnd.textContent = timeLabel(rows[rows.length - 1].at);
      chart.appendChild(xLabelEnd);
    }
    function yFor(value) {
      return bottom - (bottom - top) * (value - min) / (max - min);
    }
    active.forEach(function (metric) {
      var commands = [], points = [], segment = false;
      rows.forEach(function (row, index) {
        var value = number(row[metric.key]);
        if (value === null) { segment = false; return; }
        var x = xFor(row, index);
        if (metric.key === "rss" && points.length > 0 && row.generation !== null && number(row.generation) !== null) {
          var previous = rows[index - 1];
          if (previous && previous.generation !== row.generation) segment = false;
        }
        var y = yFor(value);
        commands.push((segment ? "L" : "M") + x.toFixed(1) + "," + y.toFixed(1));
        segment = true;
        points.push({ x: x, y: y });
      });
      var seriesClass = "diag-line diag-line-" + metric.color;
      if (points.length < 4) {
        points.forEach(function (point) {
          chart.append(svg(doc, "circle", { cx: point.x, cy: point.y, r: 3, "class": seriesClass + " diag-point" }));
        });
      } else {
        chart.append(svg(doc, "path", { d: commands.join(" "), "class": seriesClass, "data-series": metric.key }));
      }
    });
    return { rows: rows, delta: seriesEndpoints(rows, "rss").delta, axisUnit: axisUnit, xFor: xFor, yFor: yFor,
      active: active, top: top, bottom: bottom };
  }
  function processRows(doc, samples, memoryRowsInRange, latestMemory) {
    var body = doc.getElementById("diagnostic-processes");
    if (!body) return { mismatch: null };
    body.replaceChildren();
    var labels = {
      "r2o-controller": "Контроллер", "r2o-datapath": "Датапат", "r2o-panel": "Панель",
      "r2o-controller4": "Контроллер IPv4 (раздельно)", "r2o-controller6": "Контроллер IPv6 (раздельно)",
      "r2o-datapath4": "Датапат IPv4 (раздельно)", "r2o-datapath6": "Датапат IPv6 (раздельно)"
    };
    var last = samples[samples.length - 1];
    if (!last || !list(last.processes).length) {
      var empty = doc.createElement("tr"), cell = doc.createElement("td"); cell.colSpan = 3; cell.textContent = "Данные процессов недоступны."; empty.appendChild(cell); body.appendChild(empty); return { mismatch: null };
    }
    var processMono = number(last.mono_ms), memoryAt = latestMemory && number(latestMemory.time);
    var compareMono = processMono !== null && latestMemory && latestMemory.time_domain === "mono";
    var processComparable = compareMono ? processMono / 1000 : number(last.at);
    var memoryComparable = compareMono ? memoryAt : latestMemory && number(latestMemory.at);
    var timeDifference = processComparable !== null && memoryComparable !== null ? Math.abs(processComparable - memoryComparable) : null;
    var aligned = timeDifference !== null && timeDifference <= 1;
    var mismatch = null;
    list(last.processes).forEach(function (proc) {
      var first = null, firstSample = null;
      samples.some(function (sample) {
        first = list(sample.processes).filter(function (item) { return item.name === proc.name && item.pid === proc.pid && number(item.rss_kib) !== null; })[0] || null;
        if (first) firstSample = sample;
        return !!first;
      });
      var known = kibBytes(number(proc.rss_kib)), delta = known !== null && firstSample && firstSample !== last && number(first.rss_kib) !== null ? known - first.rss_kib * 1024 : null;
      if (proc.name === PRIMARY && aligned && latestMemory && number(latestMemory.rss) !== null) {
        var historyRss = seriesEndpoints(memoryRowsInRange, "rss");
        if (known !== null && Math.abs(known - latestMemory.rss) > 1024) mismatch = { process: known, memory: latestMemory.rss };
        known = latestMemory.rss;
        delta = historyRss.delta;
      }
      var row = doc.createElement("tr"), name = doc.createElement("td"), code = doc.createElement("small");
      name.textContent = labels[proc.name] || proc.name; code.textContent = proc.name; name.appendChild(code); row.appendChild(name);
      [known === null ? "—" : formatBytes(known), delta === null ? "—" : formatDeltaBytes(delta)].forEach(function (value) {
        var item = doc.createElement("td"); item.textContent = value; row.appendChild(item);
      });
      body.appendChild(row);
    });
    var note = doc.getElementById("diagnostic-process-note");
    if (note) {
      var processAt = number(last.at), memoryWallAt = latestMemory && number(latestMemory.at);
      var timeNote = timeDifference === null ? "Время одного из последних снимков неизвестно." :
        aligned ? "Снимки процессов и памяти: " + timeLabel(processAt !== null ? processAt : memoryWallAt) + "." :
          "Снимок процессов: " + timeLabel(processAt) + "; памяти: " + timeLabel(memoryWallAt) + " (разница " + formatAge(timeDifference * 1000) + ").";
      note.textContent = timeNote + " Изменение контроллера — за выбранный период графика; остальных процессов — за доступную историю того же PID.";
    }
    return { mismatch: mismatch };
  }
  function reasonText(values) {
    return list(values).map(function (value) { return reasons[value] || value; }).join(", ") || "причина не указана";
  }
  function activeLimitReasons(item) {
    return list(item && item.limit_reason).filter(function (reason) {
      return reason !== "no-current-resource-limit" && reason !== "resource-data-unavailable";
    }).sort();
  }
  function renderAimd(doc, report, last) {
    var current = doc.getElementById("diagnostic-aimd-current"), history = doc.getElementById("diagnostic-aimd-history");
    var transitions = list(report.limit_transitions).filter(function (item, index, rows) {
      var previous = rows[index - 1];
      var limiting = activeLimitReasons(item);
      if (!previous) return limiting.length > 0 || item.grow_pending === true;
      return item.measurement_limit !== previous.measurement_limit ||
        item.measurement_slots !== previous.measurement_slots || !!item.grow_pending !== !!previous.grow_pending ||
        limiting.join(",") !== activeLimitReasons(previous).join(",");
    }).reverse();
    var active = activeLimitReasons(last);
    current.closest(".diag-card").hidden = !transitions.length && !active.length && !(last && last.grow_pending);
    current.hidden = !(last && number(last.measurement_limit) !== null && number(last.measurement_slots) !== null &&
      (active.length || last.grow_pending || transitions.length));
    if (!current.hidden) {
      current.textContent = "Текущий лимит " + last.measurement_limit + " / " + last.measurement_slots +
        (active.length ? " · " + reasonText(active) : "") +
        (last.grow_pending ? " · ожидается увеличение" : "");
    }
    history.replaceChildren(...transitions.map(function (item) {
      var row = doc.createElement("li"), strong = doc.createElement("strong"), time = doc.createElement("small");
      var state = activeLimitReasons(item);
      strong.textContent = pretty(number(item.measurement_limit)) + " / " + pretty(number(item.measurement_slots)) +
        (state.length ? " · " + reasonText(state) : "");
      time.textContent = timeLabel(item.at);
      row.append(strong, time);
      return row;
    }));
  }
  function renderWarnings(doc, report, rows, processMismatch, storageMismatch) {
    var box = doc.getElementById("diagnostic-warnings");
    if (!box) return;
    box.replaceChildren();
    var notices = [], anomalies = list(report.anomalies);
    function add(kind, title, message, technical) {
      notices.push({ kind: kind, title: title, message: message, technical: technical || "" });
    }
    var lost = [
      ["events_overwritten", "записи завершений"], ["samples_overwritten", "минутные снимки"],
      ["memory_history_overwritten", "снимки памяти"], ["limit_transitions_overwritten", "переходы AIMD"],
      ["anomalies_overwritten", "аномалии"]
    ].map(function (entry) { return { key: entry[0], label: entry[1], count: number(report[entry[0]]) }; })
      .filter(function (entry) { return entry.count !== null && entry.count > 0; });
    if (lost.length) add("warning", "Часть истории вытеснена",
      "Кольцевые журналы перезаписали старые диагностические записи.",
      lost.map(function (entry) { return entry.label + " — " + entry.count; }).join("; "));
    if (processMismatch) add("warning", "Несогласованные снимки памяти",
      "В снимках с одной меткой времени RSS контроллера различается; значения оставлены у своих источников.",
      "Процессы: " + formatBytes(processMismatch.process) + "; история памяти: " + formatBytes(processMismatch.memory));
    if (storageMismatch && storageMismatch.length) add("warning", "Несовпадение объёмов в отчёте",
      "График и карточки показывают снимок истории памяти; общий отчёт содержит другие значения.", storageMismatch.join("; "));
    var growthAnomalies = anomalies.filter(function (item) { return item && item.kind === "unattributed-rss-growth"; });
    var growth = growthAnomalies[growthAnomalies.length - 1];
    if (growth) {
      add("info", "Устойчивый рост RSS",
        "За " + pretty(number(growth.window_samples)) + " снимков RSS вырос на " + formatKib(growth.rss_delta_kib) + ".",
        "Изменение учтённой памяти " + formatKib(number(growth.accounted_delta_kib)) + ".");
    }
    var unavailableRows = rows.filter(function (row) { return row.status === 1 && row.anonymous === null && row.errno !== 2; });
    var unavailable = unavailableRows.length;
    var parseErrors = rows.filter(function (row) { return row.status === 3 && row.anonymous === null; }).length;
    var detail = detailsFor(report), latest = detail && detail.latest;
    if (!unavailable && latest && latest.smaps_rollup_status === "unavailable" && latest.smaps_rollup_errno !== 2 &&
        latest.smaps_rollup_source !== "smaps-fallback" && !rows.some(function (row) { return row.anonymous !== null; })) unavailable = 1;
    if (!parseErrors && latest && latest.smaps_rollup_status === "parse-error") parseErrors = 1;
    var unavailableError = unavailableRows.find(function (row) { return row.errno !== null; });
    unavailableError = unavailableError ? unavailableError.errno : number(latest && latest.smaps_rollup_errno);
    if (unavailable) add("warning", "Не удалось прочитать подробную карту памяти",
      "Проверьте доступ к procfs и наличие процесса во время снимка.",
      unavailable + " " + sampleWord(unavailable) + (unavailableError !== null ? "; errno " + unavailableError : "; errno отсутствует"));
    if (parseErrors) add("warning", "Не удалось разобрать подробную карту памяти",
      "Повреждённый или неполный снимок исключён из графика.", parseErrors + " " + sampleWord(parseErrors));
    var writeErrors = anomalies.filter(function (item) { return item && item.kind === "diagnostic-json-write-error"; });
    var writeFailures = number(report.diagnostic_write_failures) || 0;
    if (writeFailures || writeErrors.length) {
      var writeError = writeErrors[writeErrors.length - 1];
      add("warning", "Не удалось сохранить диагностический JSON",
        "Часть отчёта могла не записаться; подробности остались в оперативном журнале.",
        "Сбоев: " + (writeFailures || writeErrors.length) + (writeError ? "; этап: " + (writeError.stage || "неизвестен") +
          (number(writeError.error_code) !== null ? "; errno " + writeError.error_code : "") : ""));
    }
    notices.forEach(function (notice) {
      var item = doc.createElement("section"), title = doc.createElement("strong"), text = doc.createElement("p");
      item.className = "diag-notice diag-notice--" + notice.kind;
      title.className = "diag-notice-title"; title.textContent = notice.title;
      text.className = "diag-notice-text"; text.textContent = notice.message;
      item.appendChild(title); item.appendChild(text);
      if (notice.technical) {
        var details = doc.createElement("details"), summary = doc.createElement("summary"), detail = doc.createElement("p");
        summary.textContent = "Технические подробности"; detail.textContent = notice.technical;
        details.appendChild(summary); details.appendChild(detail); item.appendChild(details);
      }
      box.appendChild(item);
    });
    box.hidden = notices.length === 0;
  }
  function setText(doc, id, value) {
    var node = doc.getElementById(id);
    if (node && node.textContent !== value) node.textContent = value;
  }
  function overflowText(last) {
    var names = [
      ["http_record_limit_hits", "записи"], ["http_queue_limit_hits", "очередь"],
      ["http_failure_limit_hits", "общие ошибки"], ["http_failure_record_limit_hits", "ошибки на сайт"],
      ["http_record_alloc_failures", "выделение записей"], ["http_queue_alloc_failures", "выделение очереди"],
      ["http_failure_alloc_failures", "выделение записей об ошибках"]
    ];
    var known = 0, hits = [];
    names.forEach(function (entry) {
      var count = number(last[entry[0]]);
      if (count !== null) { known++; if (count) hits.push(entry[1] + " — " + count); }
    });
    return !known ? "—" : hits.length ? hits.join(" · ") : "нет";
  }
  function storageRow(used, limit) {
    return formatBytes(used) + (number(limit) !== null && limit > 0 ? " / " + formatBytes(limit) : "");
  }
  function hasMeasurements(item, keys) {
    return !!item && keys.some(function (key) { return number(item[key]) > 0; });
  }
  function measuredSites(tracking) {
    return list(tracking && tracking.sites).filter(function (site) {
      return hasMeasurements(site, ["live_bytes", "live_objects", "peak_bytes", "created", "destroyed", "alloc_failures"]);
    });
  }
  function renderMemorySites(doc, report) {
    var listNode = doc.getElementById("diagnostic-memory-sites"), note = doc.getElementById("diagnostic-memory-tracking-coverage");
    var tracking = report.memory_tracking, sites = measuredSites(tracking);
    listNode.closest(".diag-card").hidden = !sites.length;
    if (!sites.length) { listNode.replaceChildren(); return; }
    note.textContent = tracking.coverage || "Учёт начинается с выделений после включения сбора.";
    listNode.replaceChildren(...sites.map(function (site) {
      var item = doc.createElement("li"), name = doc.createElement("strong"), facts = doc.createElement("small");
      var usage = [
        number(site.live_bytes) > 0 ? formatBytes(site.live_bytes) + " сейчас" : "",
        number(site.live_objects) > 0 ? "объектов " + site.live_objects : "",
        number(site.peak_bytes) > 0 ? "пик " + formatBytes(site.peak_bytes) : "",
        number(site.created) > 0 ? "выделено " + site.created : "",
        number(site.destroyed) > 0 ? "освобождено " + site.destroyed : "",
        number(site.alloc_failures) > 0 ? "ошибок " + site.alloc_failures : ""
      ].filter(Boolean);
      name.textContent = site.name || site.id || "Объект";
      facts.textContent = usage.join(" · ");
      item.append(name, facts);
      return item;
    }));
  }
  function technicalFact(doc, id, value) {
    var node = doc.getElementById(id);
    node.parentElement.hidden = !value;
    if (value) node.textContent = value;
  }
  function renderMadvise(doc, report) {
    var m = report.madvise || {};
    var counts = [number(m.successes) > 0 ? "успешно " + m.successes : "",
      number(m.failures) > 0 ? "ошибок " + m.failures : ""].filter(Boolean).join(" · ");
    var errors = list(m.errno).filter(function (item) { return number(item.code) > 0 && number(item.count) > 0; })
      .map(function (item) { return item.code + " × " + item.count; });
    if (number(m.other_errno_count) > 0) errors.push("прочие × " + m.other_errno_count);
    doc.getElementById("diagnostic-madvise-results").closest(".diag-card").hidden =
      !counts && !(number(m.requested_bytes) > 0) && !errors.length;
    technicalFact(doc, "diagnostic-madvise-results", counts);
    technicalFact(doc, "diagnostic-madvise-bytes", number(m.requested_bytes) > 0 ? formatBytes(m.requested_bytes) : "");
    technicalFact(doc, "diagnostic-madvise-errors", errors.join(" · "));
  }
  var outcomeLabels = {
    "plan-found": "Найден план", "direct-clear": "Прямая проба прошла",
    "stun-confirmed": "Получен STUN-ответ", "discovery-confirmed": "Получен ответ голосовой пробы",
    "failed": "Поиск завершился ошибкой", "inconclusive": "Исход не подтверждён",
    "unknown": "Исход неизвестен", "local-abort": "Поиск прерван",
    "queue-full": "Очередь заполнена", "queue-expired": "Истекло ожидание в очереди"
  };
  function unconfirmedEvent(event) {
    return ["failed", "inconclusive", "unknown", "local-abort", "queue-full", "queue-expired"].includes(event.outcome);
  }
  function renderEvents(doc, events) {
    var target = doc.getElementById("diagnostic-event-list"), empty = doc.getElementById("diagnostic-event-empty");
    var failures = events.filter(unconfirmedEvent);
    var filtered = doc.getElementById("diagnostic-event-filter").value === "unconfirmed";
    var rows = (filtered ? failures : events).slice().sort(function (a, b) { return b.at - a.at; });
    setText(doc, "diagnostic-event-summary", "Записей " + events.length + " · без подтверждения " + failures.length);
    empty.hidden = !!rows.length;
    empty.textContent = filtered ? "В журнале нет неподтверждённых исходов." : "После включения сбора завершённых подборов пока нет.";
    var key = JSON.stringify(rows);
    if (target.dataset.events === key) return;
    target.dataset.events = key;
    var expanded = new Set(Array.from(target.querySelectorAll("details[open]")).map(function (row) { return row.dataset.event; }));
    target.replaceChildren(...rows.map(function (event) {
      var li = doc.createElement("li"), details = doc.createElement("details"), title = doc.createElement("summary");
      var label = doc.createElement("strong"), outcome = doc.createElement("span"), time = doc.createElement("time");
      var info = doc.createElement("div");
      details.dataset.event = JSON.stringify([event.id, event.target, event.at, event.outcome]);
      details.open = expanded.has(details.dataset.event);
      li.dataset.unconfirmed = String(unconfirmedEvent(event));
      label.textContent = event.target || "Цель не указана";
      outcome.textContent = outcomeLabels[event.outcome] || event.outcome || "Без исхода";
      time.textContent = timeLabel(event.at);
      if (number(event.at) !== null) time.dateTime = new Date(event.at * 1000).toISOString();
      title.append(label, outcome, time);
      var facts = [];
      if (event.protocol) facts.push(event.protocol.toUpperCase());
      if (event.ip) facts.push(event.ip);
      if (number(event.elapsed_ms) !== null) facts.push("Всего " + formatAge(event.elapsed_ms));
      if (number(event.queue_ms) !== null) facts.push("В очереди " + formatAge(event.queue_ms));
      if (number(event.probe_units) !== null) facts.push("Проб: " + event.probe_units);
      [event.reason, facts.join(" · ")].filter(Boolean).forEach(function (text) {
        var line = doc.createElement("p");
        line.textContent = text;
        info.append(line);
      });
      if (!info.childElementCount) info.textContent = "Дополнительных сведений нет.";
      details.append(title, info);
      li.append(details);
      return li;
    }));
  }

  function render(report, enabled, range, size) {
    var doc = root.document, samples = list(report.samples), events = list(report.events), last = samples[samples.length - 1];
    var httpLimits = report.http_storage_limits || {};
    var data = doc.getElementById("diagnostic-data");
    var mem = report.memory_history, memorySamples = list(mem && mem.samples);
    data.hidden = !enabled || (!last && !memorySamples.length);
    if (data.hidden) return null;
    var allMemoryRows = memoryRows(report), intervalMs = number(mem && mem.sample_interval_ms) || number(report.sample_interval_ms) || 60000;
    var latest = allMemoryRows[allMemoryRows.length - 1];
    setText(doc, "diagnostic-latest-rss", formatBytes(latest && latest.rss));
    setText(doc, "diagnostic-latest-anon", formatBytes(latest && latest.rss_anon));
    setText(doc, "diagnostic-latest-count", countWithCapacity(allMemoryRows.length, mem && mem.capacity));
    renderEvents(doc, events);
    setText(doc, "diagnostic-workers-running", pretty(number(last && last.workers_running)));
    setText(doc, "diagnostic-workers-result", pretty(number(last && last.workers_result_pending)));
    setText(doc, "diagnostic-workers-join", pretty(number(last && last.workers_join_pending)));
    setText(doc, "diagnostic-workers-oldest", last && number(last.worker_oldest_age_ms) !== null ? formatAge(last.worker_oldest_age_ms) + (last.worker_oldest_type ? " · " + last.worker_oldest_type : "") : "—");
    setText(doc, "diagnostic-workers-errors", last && (number(last.worker_start_failures) !== null || number(last.worker_join_failures) !== null) ?
      pretty(number(last.worker_start_failures)) + " / " + pretty(number(last.worker_join_failures)) : "—");
    var firstRow = allMemoryRows[0], lastRow = allMemoryRows[allMemoryRows.length - 1];
    setText(doc, "diagnostic-workers-trend", firstRow && lastRow && firstRow.tasks !== null && lastRow.tasks !== null && firstRow.workers_live !== null && lastRow.workers_live !== null ?
      "задачи " + pretty(firstRow.tasks) + "→" + pretty(lastRow.tasks) + " · workers " + pretty(firstRow.workers_live) + "→" + pretty(lastRow.workers_live) : "—");
    var catalogBytes = firstDefined([lastRow && lastRow.catalog, last && last.catalog_bytes]);
    var snapshotBytes = firstDefined([lastRow && lastRow.snapshot, last && last.snapshot_bytes]);
    var haveCatalogCounts = hasMeasurements(last, ["boxes", "bindings", "plans"]);
    doc.getElementById("diagnostic-catalog-bytes").closest(".diag-card").hidden =
      !(catalogBytes > 0 || snapshotBytes > 0 || haveCatalogCounts);
    technicalFact(doc, "diagnostic-catalog-bytes", catalogBytes > 0 ? formatBytes(catalogBytes) : "");
    technicalFact(doc, "diagnostic-snapshot-bytes", snapshotBytes > 0 ? formatBytes(snapshotBytes) : "");
    technicalFact(doc, "diagnostic-catalog-counts", haveCatalogCounts ? [last.boxes, last.bindings, last.plans].map(function (value) {
      return pretty(number(value));
    }).join(" / ") : "");

    var haveRecords = hasMeasurements(last, ["http_records", "http_records_bytes"]);
    var haveQueue = hasMeasurements(last, ["http_queued", "http_queue_bytes"]);
    var haveFailures = hasMeasurements(last, ["http_failures", "http_failure_bytes"]);
    var overflow = last ? overflowText(last) : "";
    var haveOverflow = overflow && overflow !== "нет" && overflow !== "—";
    var httpBytes = firstDefined([lastRow && lastRow.http, last && last.http_bytes]);
    var haveHttp = haveRecords || haveQueue || haveFailures || haveOverflow;
    doc.getElementById("diagnostic-http-bytes").closest(".diag-card").hidden = !haveHttp;
    technicalFact(doc, "diagnostic-http-bytes", haveHttp && httpBytes > 0 ? formatBytes(httpBytes) : "");
    technicalFact(doc, "diagnostic-http-records", haveRecords ? storageRow(last.http_records_bytes, firstDefined([last.http_records_limit_bytes, httpLimits.records_bytes])) : "");
    technicalFact(doc, "diagnostic-http-queue", haveQueue ? storageRow(last.http_queue_bytes, firstDefined([last.http_queue_limit_bytes, httpLimits.queue_bytes])) : "");
    technicalFact(doc, "diagnostic-http-evidence", haveFailures ? storageRow(last.http_failure_bytes, firstDefined([last.http_failure_limit_bytes, httpLimits.failures_bytes])) : "");
    technicalFact(doc, "diagnostic-http-overflows", haveOverflow ? overflow : "");
    var matchingSample = lastRow && sampleForHistoryRow(report, lastRow.at, lastRow.time, lastRow.time_domain);
    var sharedSample = !!(matchingSample && matchingSample === last);
    var sampleMono = number(last && last.mono_ms), historyMono = lastRow && lastRow.time_domain === "mono" ? number(lastRow.time) * 1000 : null;
    var storageDifference = sampleMono !== null && historyMono !== null ? Math.abs(sampleMono - historyMono) : null;
    var storageMismatch = [];
    if (sharedSample && list(report.memory_history && report.memory_history.fields).length) {
      [["catalog_bytes", "catalog", "Каталог"], ["http_bytes", "http", "HTTP"], ["snapshot_bytes", "snapshot", "Снимки"]].forEach(function (entry) {
        if (list(report.memory_history.fields).indexOf(entry[0]) < 0 || number(lastRow[entry[1]]) === null || number(matchingSample[entry[0]]) === null) return;
        if (lastRow[entry[1]] !== matchingSample[entry[0]]) storageMismatch.push(entry[2] + ": история " + formatBytes(lastRow[entry[1]]) + ", общий снимок " + formatBytes(matchingSample[entry[0]]));
      });
    }
    var storageNote = !lastRow ? "Объём, ограничения и счётчики — из последнего общего снимка." :
      storageMismatch.length ? "Время снимка совпадает, но объёмы расходятся; карточка следует истории графика." :
      sharedSample ? "Объём, ограничения и счётчики взяты из одного снимка." :
        "Объём — снимок истории памяти " + timeLabel(lastRow.at) + "; ограничения и счётчики — общий снимок " + timeLabel(last && last.at) +
          (storageDifference !== null ? " (разница " + formatAge(storageDifference) + ")." : ".");
    setText(doc, "diagnostic-catalog-note", storageNote);
    setText(doc, "diagnostic-http-note", storageNote);
    renderMemorySites(doc, report); renderMadvise(doc, report);
    renderAimd(doc, report, last);
    var technical = doc.getElementById("diagnostic-technical");
    technical.hidden = !technical.querySelector(".diag-card:not([hidden])");
    var chart = drawMemory(doc, allMemoryRows, range, intervalMs, size);
    setText(doc, "diagnostic-memory-interval", intervalText(intervalMs, chart.axisUnit));
    setText(doc, "diagnostic-history-coverage", coverageText(chart.rows, range));
    var change = doc.getElementById("diagnostic-rss-change");
    change.hidden = chart.delta === null;
    if (!change.hidden) change.textContent = formatDeltaBytes(chart.delta) + " за период";
    var latestMemory = allMemoryRows.length ? allMemoryRows[allMemoryRows.length - 1] : null;
    var processState = processRows(doc, samples, chart.rows, latestMemory);
    renderWarnings(doc, report, allMemoryRows, processState.mismatch, storageMismatch);
    return chart;
  }
  function summary(report) {
    var samples = list(report && report.samples), events = list(report && report.events), last = samples[samples.length - 1];
    if (!last && !list(report && report.memory_history && report.memory_history.samples).length) return "Сбор включён. Ожидаем первый снимок контроллера.";
    var rss = list(last && last.processes).filter(function (p) { return p.name === PRIMARY && number(p.rss_kib) !== null; })[0];
    var first = null;
    if (rss) samples.some(function (sample) {
      first = list(sample.processes).filter(function (p) { return p.name === rss.name && p.pid === rss.pid && number(p.rss_kib) !== null; })[0] || null;
      return !!first;
    });
    var failures = events.filter(unconfirmedEvent).length;
    var memory = report.memory_history || {}, detail = detailsFor(report);
    var memoryRowsLatest = memoryRows(report), lastMemory = memoryRowsLatest[memoryRowsLatest.length - 1];
    var rssAnon = lastMemory && lastMemory.rss_anon !== null ? lastMemory.rss_anon / 1024 :
      number(list(last && last.processes).filter(function (p) { return p.name === PRIMARY; })[0] && list(last && last.processes).filter(function (p) { return p.name === PRIMARY; })[0].anon_kib);
    var catalogBytes = firstDefined([last && last.catalog_bytes, lastMemory && lastMemory.catalog]);
    var tracker = report.memory_tracking || {}, sites = measuredSites(tracker), madvise = report.madvise || {}, anomalies = list(report.anomalies);
    var extras = (rssAnon === null ? "" : " RssAnon: " + formatKib(rssAnon) + ".") +
      (catalogBytes !== null ? " Память каталога: " + formatBytes(catalogBytes) + "." : "") +
      (sites.length ? " Инструментированные подсистемы: " + sites.map(function (site) { return (site.name || site.id) + " " + formatBytes(site.live_bytes); }).join(", ") + "." : "") +
      (hasMeasurements(madvise, ["successes", "failures", "requested_bytes"]) ? " madvise успешно / ошибка: " + pretty(number(madvise.successes)) + " / " + pretty(number(madvise.failures)) + "." : "") +
      (anomalies.some(function (item) { return item.kind === "unattributed-rss-growth"; }) ? " Зафиксирован устойчивый рост RSS без сопоставимого роста учтённых объектов; это не подтверждает утечку." : "");
    var latestDetail = detail && detail.latest;
    if (latestDetail && latestDetail.smaps_rollup_source === "smaps-fallback") extras += " Anonymous и Private_Dirty получены из smaps.";
    return "Снимков: " + countWithCapacity(samples.length, report.sample_capacity) + "; завершений поиска: " + countWithCapacity(events.length, report.event_capacity) +
      ", без подтверждённого результата: " + failures + ". " + (rss ? "RSS контроллера: " + formatKib(rss.rss_kib) +
      (first ? " (" + ((rss.rss_kib - first.rss_kib) >= 0 ? "+" : "") + ((rss.rss_kib - first.rss_kib) / 1024).toFixed(1) + " за историю этого PID)" : "") + ". " : "") +
      "Снимков памяти: " + countWithCapacity(list(memory.samples).length, memory.capacity) + extras;
  }
  if (typeof module === "object" && module.exports) module.exports = {
    summary: summary, memoryRows: memoryRows, rowsInRange: rowsInRange,
    seriesEndpoints: seriesEndpoints, formatBytes: formatBytes, coverageText: coverageText
  };
  if (!root.document || !root.fetch) return;
  function boot() {
    var doc = root.document, toggle = doc.getElementById("diagnostic-toggle"), status = doc.getElementById("diagnostic-status");
    var download = doc.getElementById("diagnostic-download"), state = doc.getElementById("diagnostic-state");
    var refreshButton = doc.getElementById("diagnostic-refresh"), cursor = doc.getElementById("diagnostic-cursor");
    var slider = doc.getElementById("diagnostic-cursor-input"), graph = doc.getElementById("diagnostic-memory-chart");
    if (!toggle || !status || !download) return;
    var stopDialog = doc.getElementById("diagnostic-stop-dialog"), eventFilter = doc.getElementById("diagnostic-event-filter");
    var clearHistory = doc.getElementById("diagnostic-clear");
    var rangeButtons = doc.querySelectorAll("[data-memory-range]");
    var params = new URL(root.location.href).searchParams;
    var range = params.get("diag-period") === "24" ? 24 : 2;
    eventFilter.value = params.get("diag-outcomes") === "unconfirmed" ? "unconfirmed" : "all";
    var enabled, paused = false, failed = false, busy = false, currentReport = {}, chart, selectedAt;
    var reportBytes = null, poll, request, pendingSince = 0, resizeFrame;
    var plotSize = { width: 320, height: 240 };

    function saveOption(key, value) {
      var url = new URL(root.location.href);
      if (value) url.searchParams.set(key, value); else url.searchParams.delete(key);
      root.history.replaceState(root.history.state, "", url);
    }
    function markRange() {
      rangeButtons.forEach(function (button) {
        button.setAttribute("aria-pressed", String(Number(button.dataset.memoryRange) === range));
      });
    }
    markRange();

    function cursorAt(index) {
      if (!chart || !chart.xFor) return;
      var row = chart.rows[index];
      if (!row) return;
      var old = graph.querySelector(".diag-cursor-mark");
      if (old) old.remove();
      var x = chart.xFor(row, index);
      var marker = svg(doc, "g", { "class": "diag-cursor-mark", "aria-hidden": "true" });
      marker.append(svg(doc, "line", { x1: x, x2: x, y1: chart.top, y2: chart.bottom, "class": "diag-cursor-line" }));
      chart.active.forEach(function (metric) {
        var value = number(row[metric.key]);
        if (value !== null) marker.append(svg(doc, "circle", {
          cx: x, cy: chart.yFor(value), r: 4, "class": "diag-point diag-line diag-line-" + metric.color
        }));
      });
      graph.append(marker);
      var label = timeLabel(row.at) + " · RSS " + formatBytes(row.rss) + " · анонимная " + formatBytes(row.rss_anon);
      setText(doc, "diagnostic-cursor-value", label);
      slider.setAttribute("aria-valuetext", label);
    }

    function redraw() {
      chart = render(currentReport, enabled, range, plotSize);
      cursor.hidden = !chart || !chart.xFor || chart.rows.length < 2;
      var reportSize = doc.getElementById("diagnostic-report-size");
      reportSize.hidden = !chart || number(reportBytes) === null;
      if (!reportSize.hidden) reportSize.textContent = "Размер JSON: " + formatBytes(reportBytes);
      if (cursor.hidden) return;
      var index = selectedAt === undefined ? -1 : chart.rows.findIndex(function (row) { return row.at === selectedAt; });
      if (index < 0) index = chart.rows.length - 1;
      slider.max = String(chart.rows.length - 1);
      slider.value = String(index);
      slider.disabled = chart.rows.length < 2;
      cursorAt(index);
    }

    function visible() { return !doc.hidden && !doc.getElementById("diagnostics").hidden; }

    function renderState() {
      var last = list(currentReport.samples).at(-1), at = last ? number(last.at) : null;
      var interval = number(currentReport.sample_interval_ms) || 60000;
      var waiting = pendingSince && Date.now() - pendingSince < 10000;
      var stale = at !== null && Date.now() - at * 1000 > 2 * interval;
      var phase = failed ? "error" : enabled === undefined ? "loading" : !enabled ? "off" : paused ? "paused"
        : at === null ? (waiting ? "pending" : "late") : stale ? "late" : "ready";
      var labels = {
        loading: ["Проверяем", "Читаем состояние сбора…"],
        off: ["Выключен", "Минутные снимки памяти и исходы подбора сохраняются на роутере после включения."],
        paused: ["Остановлен", at === null ? "Запись приостановлена." : "Запись приостановлена. Последний снимок " + timeLabel(at)],
        pending: ["Первый снимок", "Сбор включён. Ждём первый снимок контроллера…"],
        late: ["Данные задерживаются", at === null ? "Первый снимок ещё недоступен. Проверьте состояние контроллера." : "Снимок за " + timeLabel(at) + " устарел. Показан последний доступный отчёт."],
        ready: ["Включён", "Последний снимок " + timeLabel(at) + " · шаг " + formatAge(interval)],
        error: ["Ошибка связи", "Не удалось получить отчёт с роутера. Повторите запрос."]
      };
      var changed = state.textContent !== labels[phase][0];
      setText(doc, "diagnostic-state", labels[phase][0]);
      if (changed && root.R2oPanelMotion) root.R2oPanelMotion.reveal(state);
      setText(doc, "diagnostic-status", labels[phase][1]);
      state.dataset.enabled = String(enabled === true);
      state.dataset.phase = phase;
      toggle.disabled = busy || enabled === undefined;
      toggle.textContent = paused ? "Возобновить сбор" : enabled ? "Остановить сбор" : "Включить сбор";
      toggle.setAttribute("data-variant", enabled && !paused ? "ghost" : "primary");
      clearHistory.hidden = !enabled;
      clearHistory.disabled = busy;
      download.hidden = !enabled || failed || at === null;
      refreshButton.hidden = !enabled && !failed;
      refreshButton.disabled = busy || !!request;
    }

    function schedule() {
      root.clearTimeout(poll);
      if (!visible() || busy) return;
      var last = list(currentReport.samples).at(-1);
      var interval = number(currentReport.sample_interval_ms) || 60000;
      var untilNext = last && number(last.at) !== null ? last.at * 1000 + interval + 1200 - Date.now() : 0;
      var delay = failed ? 5000 : !enabled || paused ? 30000 : !last
        ? (Date.now() - pendingSince < 10000 ? 900 : 5000)
        : Math.min(interval, Math.max(untilNext > 0 ? 2000 : 8000, untilNext));
      poll = root.setTimeout(refresh, delay);
    }

    function refresh() {
      if (request) return request;
      var controller = new AbortController();
      var timeout = root.setTimeout(function () { controller.abort(); }, 6000);
      request = root.fetch("/api/diagnostics?report", { cache: "no-store", signal: controller.signal }).then(function (response) {
        if (!response.ok && response.status !== 503) throw new Error("HTTP " + response.status);
        return response.json().then(function (report) {
          failed = false;
          enabled = report.enabled === true;
          paused = enabled && response.headers.get("X-R2O-Diagnostics-Paused") === "true";
          var pending = enabled && !list(report.samples).length;
          if (pending && !pendingSince) pendingSince = Date.now();
          if (!pending) pendingSince = 0;
          var length = response.headers.get("Content-Length");
          reportBytes = length === null ? null : Number(length);
          currentReport = report;
          if (!enabled) selectedAt = undefined;
          redraw();
        });
      }).catch(function () { failed = true; }).finally(function () {
        root.clearTimeout(timeout);
        request = null;
        renderState();
        schedule();
      });
      renderState();
      return request;
    }

    function controlCollection(action) {
      if (busy || enabled === undefined) return;
      busy = true;
      root.clearTimeout(poll);
      renderState();
      Promise.resolve(request).then(function () {
        return root.fetch("/api/diagnostics?" + action, { method: "POST", cache: "no-store" });
      }).then(function (response) {
        if (!response.ok) throw new Error(String(response.status));
        return response.json();
      }).then(function (reply) {
        enabled = reply.enabled === true;
        pendingSince = enabled ? Date.now() : 0;
        if (action === "clear") {
          selectedAt = undefined;
          currentReport = {};
        }
        failed = false;
        redraw();
        return refresh();
      }).catch(function (error) {
        setText(doc, "diagnostic-status", error.message === "403" ? "Управление сбором недоступно в этой панели." : "Не удалось изменить состояние сбора.");
      }).finally(function () {
        busy = false;
        renderState();
        schedule();
      });
    }

    toggle.addEventListener("click", function () {
      controlCollection(enabled && !paused ? "pause" : "enable");
    });
    clearHistory.addEventListener("click", function () {
      stopDialog.returnValue = "cancel";
      stopDialog.showModal();
    });
    stopDialog.addEventListener("close", function () {
      if (stopDialog.returnValue === "clear" && enabled) controlCollection("clear");
    });
    rangeButtons.forEach(function (button) {
      button.addEventListener("click", function () {
        var nextRange = Number(button.dataset.memoryRange);
        if (nextRange === range) return;
        range = nextRange;
        saveOption("diag-period", range === 24 ? "24" : "");
        markRange();
        redraw();
        if (!graph.hasAttribute("hidden") && !root.matchMedia("(prefers-reduced-motion: reduce)").matches) {
          graph.getAnimations().forEach(function (animation) { animation.cancel(); });
          graph.animate([{ opacity: .68 }, { opacity: 1 }], { duration: 170, easing: "ease-out" });
        }
      });
    });
    doc.querySelectorAll("[data-memory-series]").forEach(function (input) { input.addEventListener("change", redraw); });
    eventFilter.addEventListener("change", function () {
      saveOption("diag-outcomes", eventFilter.value === "unconfirmed" ? "unconfirmed" : "");
      renderEvents(doc, list(currentReport.events));
    });
    function selectSnapshot(index) {
      if (!chart || !chart.rows[index]) return;
      slider.value = String(index);
      selectedAt = index === chart.rows.length - 1 ? undefined : chart.rows[index].at;
      cursorAt(index);
    }
    slider.addEventListener("input", function () { selectSnapshot(Number(slider.value)); });
    graph.addEventListener("click", function (event) {
      if (cursor.hidden) return;
      var rect = graph.getBoundingClientRect();
      var x = (event.clientX - rect.left) / rect.width * plotSize.width;
      var nearest = 0, distance = Infinity;
      chart.rows.forEach(function (row, index) {
        var offset = Math.abs(chart.xFor(row, index) - x);
        if (offset < distance) { nearest = index; distance = offset; }
      });
      selectSnapshot(nearest);
    });
    refreshButton.addEventListener("click", refresh);
    function wake() {
      root.clearTimeout(poll);
      if (visible() && !busy) refresh();
    }
    root.addEventListener("hashchange", function () { root.setTimeout(wake, 0); });
    doc.addEventListener("visibilitychange", wake);
    var plot = doc.getElementById("diagnostic-plot");
    new root.ResizeObserver(function ([entry]) {
      var width = Math.floor(entry.contentRect.width), height = Math.floor(entry.contentRect.height);
      if (!width || !height || (width === plotSize.width && height === plotSize.height)) return;
      plotSize = { width: width, height: height };
      if (!resizeFrame) resizeFrame = root.requestAnimationFrame(function () {
        resizeFrame = null;
        if (visible()) {
          redraw();
          plot.dataset.measured = "true";
        }
      });
    }).observe(plot);
    refresh();
  }
  if (root.document.readyState === "loading") root.document.addEventListener("DOMContentLoaded", boot); else boot();
})(typeof window !== "undefined" ? window : this);
