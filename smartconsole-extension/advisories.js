/*
 * Advisory Watch — SmartConsole extension.
 * Reads the selected gateway from the SmartConsole extension context, then fetches
 * matched + unassigned advisories from advisory-watch's own local API (same origin
 * as this page).
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
  var threshold = gwUid && adv.gateway_known_threshold ? adv.gateway_known_threshold[gwUid] : null;
  var isEos = gwUid && adv.eos_gateway_uids && adv.eos_gateway_uids.indexOf(gwUid) !== -1;
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
    gapBadge.innerText = "Take " + gap[0] + " → " + gap[1] + " needed";
    cellStatus.appendChild(gapBadge);
  } else if (threshold !== null && threshold !== undefined) {
    var thresholdBadge = document.createElement("span");
    thresholdBadge.className = "badge badge-review";
    thresholdBadge.innerText = "Verify Take > " + threshold;
    cellStatus.appendChild(thresholdBadge);
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

function fetchAdvisories(uid, name) {
  // name lets the server fall back to self-reported data (gateway-report.sh)
  // when this uid is unknown to the polled inventory — e.g. a gateway on a
  // management server the advisory-watch operator has no credentials for.
  var url = "/api/gateway/" + encodeURIComponent(uid) + "/advisories";
  if (name) {
    url += "?name=" + encodeURIComponent(name);
  }
  fetch(url)
    .then(function (resp) { return resp.json(); })
    .then(function (data) { renderAdvisories(data, uid); })
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
  fetchAdvisories(objects[0].uid, objects[0].name);
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
    // optionally &name=...) from the URL.
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
