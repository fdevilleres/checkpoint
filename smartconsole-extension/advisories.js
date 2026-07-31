/*
 * Advisory Watch — SmartConsole extension.
 * Reads the selected gateway from the SmartConsole extension context, then fetches
 * matched + unassigned advisories from advisory-watch's own local API (same origin
 * as this page).
 *
 * When the gateway is unknown to this server (not in its polled inventory, no
 * self-report on file) and SmartConsole granted the "get-read-only-session"
 * permission, this tries to auto-detect the gateway's version + installed Jumbo
 * Hotfix Take itself -- using the CURRENT USER'S OWN read-only Management API
 * session, obtained from the extension context, never advisory-watch's server.
 * No credentials are shared with advisory-watch in either direction. If that
 * isn't possible (permission not granted, call fails, management server
 * unreachable from here), the tab falls back to telling the tester to run
 * gateway-report.sh manually -- see MOP-AW-001 section 6.
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
  // "inferred" = we only had the vulnerability threshold, so the Take shown is the
  // lowest one above the vulnerable range, not the published fix Take. Mark it.
  var inferred = gwUid && adv.gateway_take_source && adv.gateway_take_source[gwUid] === "inferred";
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
    gapBadge.innerText = "Install JHF Take " + gap[1] + (inferred ? " (approx.)" : "");
    gapBadge.title = "Jumbo Hotfix Accumulator Take " + gap[1] + " or above must be installed. "
      + "Currently installed: Take " + gap[0] + "." + inferredNote;
    cellStatus.appendChild(gapBadge);
  } else if (requiredOnly !== null && requiredOnly !== undefined) {
    var requiredBadge = document.createElement("span");
    requiredBadge.className = "badge badge-review";
    requiredBadge.innerText = "Install JHF Take " + requiredOnly + (inferred ? " (approx.)" : "")
      + " — installed Take unknown";
    requiredBadge.title = "Jumbo Hotfix Accumulator Take " + requiredOnly + " or above is required, "
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
 * Calls show-software-packages-per-targets directly against the Management API,
 * using the read-only session SmartConsole granted THIS extension instance for
 * THIS user -- never advisory-watch's own credentials, which it doesn't have for
 * a foreign management server anyway. Requires "get-read-only-session" in
 * extension.json's requested-permissions; api comes from the get-context
 * response's "management-server-api" field.
 *
 * api.url's own convention is undocumented, and confirmed live to already
 * include "/web_api" (a naive "+ /web_api/<command>" produced a real, logged
 * ".../web_api/web_api/show-..." request that could only ever 404/CORS-fail
 * regardless of the server's actual policy) -- so this only appends it when
 * not already present, tolerating a trailing slash either way.
 */
function apiCommandUrl(baseUrl, command) {
  var base = (baseUrl || "").replace(/\/+$/, "");
  if (!/\/web_api$/i.test(base)) {
    base += "/web_api";
  }
  return base + "/" + command;
}

function fetchInstalledTake(api, gatewayName) {
  return fetch(apiCommandUrl(api.url, "show-software-packages-per-targets"), {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-chkp-sid": api.sid },
    body: JSON.stringify({ targets: [gatewayName], display: { installed: "yes" } })
  })
    .then(function (resp) {
      if (!resp.ok) {
        throw new Error("show-software-packages-per-targets HTTP " + resp.status);
      }
      return resp.json();
    })
    .then(function (data) {
      var target = data.targets && data.targets[0];
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
 * via the granted read-only session, submit it, then let the caller re-fetch
 * advisories now that a report exists. Resolves false on any failure so the
 * caller can fall back to the manual-script banner rather than hang. Each
 * failure stage is reported distinctly -- "no context at all" (permission
 * never granted, most likely an install that predates this feature) is a very
 * different problem from "context present but the fetch itself failed" (most
 * likely the tester's own management server uses a certificate the browser
 * doesn't trust, which a plain fetch() has no way to work around). */
function tryAutoDetect(mgmtApi, gwVersion, gwName) {
  if (!mgmtApi) {
    reportClientLog(gwName, "no-context",
      "management-server-api missing from get-context -- permission not granted, " +
      "or this install predates the permission being added to the manifest");
    return Promise.resolve(false);
  }
  if (!mgmtApi.sid || !mgmtApi.url) {
    reportClientLog(gwName, "incomplete-context", JSON.stringify(mgmtApi));
    return Promise.resolve(false);
  }
  if (!gwVersion || !gwName) {
    reportClientLog(gwName, "missing-basics", "gwVersion=" + gwVersion + " gwName=" + gwName);
    return Promise.resolve(false);
  }
  return fetchInstalledTake(mgmtApi, gwName)
    .then(function (take) { return submitReport(gwName, gwVersion, take); })
    .then(function (result) { return !!(result && result.ok); })
    .catch(function (err) {
      reportClientLog(gwName, "fetch-failed", (err && err.message) || String(err));
      console.error("Auto-detection failed, falling back to manual self-report:", err);
      return false;
    });
}

function fetchAdvisories(uid, name, mgmtApi, gwVersion, allowAutoDetect) {
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
        tryAutoDetect(mgmtApi, gwVersion, name).then(function (detected) {
          if (detected) {
            // Re-fetch now that a report exists; don't attempt auto-detection
            // again even if this second call somehow still comes back unknown.
            fetchAdvisories(uid, name, mgmtApi, gwVersion, false);
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
  // Present (with a usable sid) only when extension.json requested
  // "get-read-only-session" and SmartConsole granted it for this session.
  var mgmtApi = obj["management-server-api"];
  fetchAdvisories(gw.uid, gw.name, mgmtApi, gw.version, true);
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
