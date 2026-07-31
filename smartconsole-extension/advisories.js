/*
 * Advisory Watch — SmartConsole extension.
 * Reads the selected gateway from the SmartConsole extension context, then fetches
 * matched + unassigned advisories from advisory-watch's own local API (same origin
 * as this page).
 *
 * When the gateway is unknown to this server (not in its polled inventory, no
 * self-report on file), this tries to auto-detect the gateway's version +
 * installed Jumbo Hotfix Take itself -- via smxProxy's "run-readonly-command"
 * bridge (requires "get-read-only-session" + "run-read-only-commands" in
 * extension.json), which runs the read-only Management API call inside the
 * native SmartConsole host under the CURRENT USER'S OWN session and returns
 * the result by callback. This is NOT a browser fetch() to the management
 * server -- that path was tried first and confirmed always CORS-blocked
 * (the Management API never sends Access-Control-Allow-Origin, so no
 * client-side fix exists); smxProxy sidesteps it entirely since no
 * cross-origin request is ever made. No credentials are shared with
 * advisory-watch in either direction. If auto-detection isn't possible
 * (permission not granted, older SmartConsole, call fails), the tab falls
 * back to telling the tester to run gateway-report.sh manually -- see
 * MOP-AW-001 section 6.
 */

function severityBadgeClass(severity) {
  switch ((severity || "").toUpperCase()) {
    case "CRITICAL": return "badge-critical";
    case "HIGH": return "badge-high";
    case "MEDIUM": return "badge-medium";
    default: return "badge-low";
  }
}

function addRow(table, adv, gwUid) {
  var row = table.insertRow(-1);

  var cellCve = row.insertCell(0);
  var link = document.createElement("a");
  link.href = adv.source_url || "#";
  link.target = "_blank";
  link.innerText = adv.cve_id;
  cellCve.appendChild(link);

  var cellSeverity = row.insertCell(1);
  if (adv.cvss !== null && adv.cvss !== undefined) {
    var sevBadge = document.createElement("span");
    sevBadge.className = "badge " + severityBadgeClass(adv.severity);
    sevBadge.innerText = adv.cvss + " " + (adv.severity || "");
    cellSeverity.appendChild(sevBadge);
  }
  if (adv.kev) {
    var kevBadge = document.createElement("span");
    kevBadge.className = "badge badge-kev";
    kevBadge.innerText = "KEV";
    cellSeverity.appendChild(kevBadge);
  }

  var cellStatus = row.insertCell(2);
  var gap = gwUid && adv.gateway_take_gap ? adv.gateway_take_gap[gwUid] : null;
  var requiredOnly = gwUid && adv.gateway_required_take ? adv.gateway_required_take[gwUid] : null;
  var isEos = gwUid && adv.eos_gateway_uids && adv.eos_gateway_uids.indexOf(gwUid) !== -1;
  var takeSource = gwUid && adv.gateway_take_source ? adv.gateway_take_source[gwUid] : null;
  // "latest" = Check Point's own JHF downloads page for this version, not just the
  // Take that happens to fix this one CVE -- the number to actually install.
  var isLatest = takeSource === "latest";
  // "inferred" = we only had the vulnerability threshold, so the Take shown is the
  // lowest one above the vulnerable range, not the published fix Take. Mark it.
  var inferred = takeSource === "inferred";
  var inferredNote = inferred
    ? " This is the lowest Take above the vulnerable range, not a confirmed fix Take -- "
      + "open the advisory for the exact Jumbo Hotfix Accumulator that carries the fix."
    : "";
  if (adv.resolved_not_applicable) {
    var resolvedBadge = document.createElement("span");
    resolvedBadge.className = "badge badge-resolved";
    resolvedBadge.innerText = "Not applicable";
    cellStatus.appendChild(resolvedBadge);
  } else if (isEos) {
    var eosBadge = document.createElement("span");
    eosBadge.className = "badge badge-review";
    eosBadge.innerText = "EOS — upgrade needed";
    cellStatus.appendChild(eosBadge);
  } else if (gap) {
    var gapBadge = document.createElement("span");
    gapBadge.className = "badge badge-critical";
    gapBadge.innerText = isLatest
      ? "Update to JHF Take " + gap[1] + " (latest)"
      : "Install JHF Take " + gap[1] + (inferred ? " (approx.)" : "");
    gapBadge.title = (isLatest
        ? "Take " + gap[1] + " is the latest Jumbo Hotfix Accumulator available for this version. "
        : "Jumbo Hotfix Accumulator Take " + gap[1] + " or above must be installed. ")
      + "Currently installed: Take " + gap[0] + "." + inferredNote;
    cellStatus.appendChild(gapBadge);
  } else if (requiredOnly !== null && requiredOnly !== undefined) {
    var requiredBadge = document.createElement("span");
    requiredBadge.className = "badge badge-review";
    requiredBadge.innerText = (isLatest
        ? "Update to JHF Take " + requiredOnly + " (latest)"
        : "Install JHF Take " + requiredOnly + (inferred ? " (approx.)" : ""))
      + " — installed Take unknown";
    requiredBadge.title = (isLatest
        ? "Take " + requiredOnly + " is the latest Jumbo Hotfix Accumulator available for this version, "
        : "Jumbo Hotfix Accumulator Take " + requiredOnly + " or above is required, ")
      + "but the Take currently installed on this gateway couldn't be read automatically."
      + inferredNote;
    cellStatus.appendChild(requiredBadge);
  } else if (adv.needs_review) {
    var reviewBadge = document.createElement("span");
    reviewBadge.className = "badge badge-review";
    reviewBadge.innerText = "Needs review";
    cellStatus.appendChild(reviewBadge);
  } else {
    cellStatus.innerText = "Matched";
  }

  var cellSummary = row.insertCell(3);
  cellSummary.innerText = adv.title || adv.summary || "";
  cellSummary.className = "might-overflow";

  var cellSource = row.insertCell(4);
  var sourceLink = document.createElement("a");
  sourceLink.href = adv.source_url || "#";
  sourceLink.target = "_blank";
  sourceLink.innerText = "NVD";
  cellSource.appendChild(sourceLink);
}

function showUnknownBanner() {
  var banner = document.createElement("div");
  banner.className = "unknown-banner";
  banner.innerHTML =
    "<strong>This gateway hasn't been checked yet.</strong> It isn't in this server's " +
    "polled inventory, automatic detection wasn't possible, and no self-report has been " +
    "submitted for it. Run <code>gateway-report.sh</code> from the SmartConsole Scripts " +
    "Repository against this gateway, then reopen this tab.";
  document.body.insertBefore(banner, document.body.firstChild);
}

function renderAdvisories(data, gwUid) {
  removeLoader();

  var matched = data.matched || [];
  var unassigned = data.unassigned || [];
  var resolved = data.resolved || [];

  if (matched.length > 0) {
    var matchedTable = document.getElementById("matchedTable");
    matched.forEach(function (adv) { addRow(matchedTable, adv, gwUid); });
    document.getElementById("matched-section").style.display = "block";
  } else {
    document.getElementById("matched-empty-message").style.display = "block";
  }

  if (unassigned.length > 0) {
    var unassignedTable = document.getElementById("unassignedTable");
    unassigned.forEach(function (adv) { addRow(unassignedTable, adv); });
    document.getElementById("unassigned-section").style.display = "block";
  }

  if (resolved.length > 0) {
    var resolvedTable = document.getElementById("resolvedTable");
    resolved.forEach(function (adv) { addRow(resolvedTable, adv); });
    document.getElementById("resolved-section").style.display = "block";
  }
}

/*
 * The installed-Take rule mirrors hotfix.py exactly, so a testers's browser and
 * advisory-watch's own collector never disagree on how to read the same API
 * response: no installed packages at all -> Take 0 (a confirmed answer, not
 * "unknown"); otherwise the highest Take found in a non-"major"-category
 * package-id's trailing "_T<N>[_FULL].tgz", or null if nothing matched (a real
 * "can't tell" case -- never guessed at).
 */
function parseInstalledTake(packages) {
  if (!packages || packages.length === 0) {
    return 0;
  }
  var takes = [];
  packages.forEach(function (pkg) {
    if (pkg.category === "major") {
      return;
    }
    var m = /_T(\d+)(?:_FULL)?\.tgz$/i.exec(pkg["package-id"] || "");
    if (m) {
      takes.push(parseInt(m[1], 10));
    }
  });
  return takes.length > 0 ? Math.max.apply(null, takes) : null;
}

/*
 * Calls show-software-packages-per-targets through smxProxy's "run-readonly-command"
 * bridge -- NOT a browser fetch() against the Management API. That distinction is
 * the whole point: a direct fetch() from this page's origin to a tester's own
 * management server is blocked by CORS every time (confirmed live -- the
 * Management API never sends Access-Control-Allow-Origin, so no client-side fix
 * exists). smxProxy.sendRequest runs the command inside the native SmartConsole
 * host using the current user's own session and returns the result via a
 * callback, so no cross-origin browser request ever happens. Requires
 * "run-read-only-commands" (alongside "get-read-only-session") in
 * extension.json's requested-permissions.
 *
 * smxProxy's callback argument is a *name*, not a function reference -- it calls
 * window[name](result) -- so each call registers a one-off global callback and
 * cleans it up once invoked.
 */
var _smxCallbackSeq = 0;
function callReadOnlyCommand(command, parameters) {
  return new Promise(function (resolve, reject) {
    var cbName = "_awRoCb" + (++_smxCallbackSeq);
    window[cbName] = function (result) {
      delete window[cbName];
      resolve(result);
    };
    try {
      smxProxy.sendRequest("run-readonly-command", { command: command, parameters: parameters }, cbName);
    } catch (e) {
      delete window[cbName];
      reject(e);
    }
  });
}

/* Management API responses that come back through smxProxy are sometimes
 * wrapped in a "response" field and sometimes not, depending on SmartConsole
 * version -- unwrap defensively either way. */
function unwrapSmxResponse(raw) {
  if (!raw) {
    return null;
  }
  var data = raw.response !== undefined ? raw.response : raw;
  return Array.isArray(data) ? data[0] || {} : data;
}

function fetchInstalledTake(gatewayName) {
  return callReadOnlyCommand("show-software-packages-per-targets", {
    targets: [gatewayName],
    display: { installed: "yes" }
  }).then(function (raw) {
    var data = unwrapSmxResponse(raw);
    var target = data && data.targets && data.targets[0];
    var packages = target && target.packages && target.packages.installed;
    return parseInstalledTake(packages);
  });
}

/* Submits an auto-detected {name, version, take} the same way gateway-report.sh
 * does -- same endpoint, same shape -- so the rest of the pipeline (server.py,
 * reported.py, matcher.py) treats an auto-detected report identically to a
 * manually-submitted one. */
function submitReport(name, version, take) {
  return fetch("/api/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name: name, version: version, take: take })
  }).then(function (resp) { return resp.json(); });
}

/* Best-effort diagnostic channel: lets us see WHY auto-detection failed on a
 * tester's machine (permission never granted vs. a network/TLS error calling
 * their own management server) without needing console access on their side.
 * Never affects matching -- purely observational, and failures here are
 * swallowed so logging itself can never break the fallback path. */
function reportClientLog(name, stage, detail) {
  try {
    fetch("/api/client-log", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: name, stage: stage, detail: String(detail) })
    }).catch(function () {});
  } catch (e) { /* ignore */ }
}

/* Only attempted once per tab load (no retry loop): detect the installed Take
 * via smxProxy's run-readonly-command bridge, submit it, then let the caller
 * re-fetch advisories now that a report exists. Resolves false on any failure
 * so the caller can fall back to the manual-script banner rather than hang.
 * "no-smxproxy" (dev-shim page load, not real SmartConsole) is a different
 * problem from "call-failed" (permission not granted, or the command itself
 * errored) -- reported distinctly so a tester's log tells us which. */
function tryAutoDetect(gwVersion, gwName) {
  if (typeof smxProxy === "undefined") {
    reportClientLog(gwName, "no-smxproxy", "not running inside SmartConsole");
    return Promise.resolve(false);
  }
  if (!gwVersion || !gwName) {
    reportClientLog(gwName, "missing-basics", "gwVersion=" + gwVersion + " gwName=" + gwName);
    return Promise.resolve(false);
  }
  return fetchInstalledTake(gwName)
    .then(function (take) { return submitReport(gwName, gwVersion, take); })
    .then(function (result) { return !!(result && result.ok); })
    .catch(function (err) {
      reportClientLog(gwName, "call-failed", (err && err.message) || String(err));
      console.error("Auto-detection failed, falling back to manual self-report:", err);
      return false;
    });
}

function fetchAdvisories(uid, name, gwVersion, allowAutoDetect) {
  var url = "/api/gateway/" + encodeURIComponent(uid) + "/advisories";
  if (name) {
    // name lets the server fall back to self-reported data (gateway-report.sh,
    // or auto-detection below) when this uid is unknown to the polled inventory
    // -- e.g. a gateway on a management server advisory-watch has no credentials
    // for.
    url += "?name=" + encodeURIComponent(name);
  }
  fetch(url)
    .then(function (resp) { return resp.json(); })
    .then(function (data) {
      if (data.unknown && allowAutoDetect) {
        tryAutoDetect(gwVersion, name).then(function (detected) {
          if (detected) {
            // Re-fetch now that a report exists; don't attempt auto-detection
            // again even if this second call somehow still comes back unknown.
            fetchAdvisories(uid, name, gwVersion, false);
          } else {
            removeLoader();
            showUnknownBanner();
            renderAdvisories(data, uid);
          }
        });
        return;
      }
      renderAdvisories(data, uid);
    })
    .catch(function (err) {
      removeLoader();
      var message = document.createElement("p");
      message.innerText = "Failed to load advisories: " + err;
      document.body.appendChild(message);
    });
}

function onContext(obj) {
  var objects = obj.event.objects;
  if (!objects || objects.length === 0) {
    removeLoader();
    var message = document.createElement("p");
    message.innerText = "No gateway selected.";
    document.body.appendChild(message);
    return;
  }
  var gw = objects[0];
  fetchAdvisories(gw.uid, gw.name, gw.version, true);
}

function removeLoader() {
  var loader = document.getElementById("loader-text");
  if (loader) {
    loader.parentNode.removeChild(loader);
  }
}

function showContext() {
  if (typeof smxProxy !== "undefined") {
    smxProxy.sendRequest("get-context", null, "onContext");
  } else {
    // Dev-only shim for testing outside SmartConsole: read ?uid=... (and
    // optionally &name=...) from the URL. No management-server-api available
    // in this mode, so auto-detection is never attempted here.
    var params = new URLSearchParams(window.location.search);
    var uid = params.get("uid");
    if (!uid) {
      removeLoader();
      var message = document.createElement("p");
      message.innerText = "Dev mode: append ?uid=<gateway-uid> to the URL to test.";
      document.body.appendChild(message);
      return;
    }
    onContext({ event: { objects: [{ uid: uid, name: params.get("name") || "", type: "simple-gateway" }] } });
  }
}
