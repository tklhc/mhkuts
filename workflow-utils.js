function round(value, digits = 4) {
  const m = 10 ** digits;
  return Math.round(Number(value || 0) * m) / m;
}

function computeStd(values, mean) {
  if (!Array.isArray(values) || values.length < 2) return 0;
  const variance = values.reduce((s, v) => s + ((v - mean) ** 2), 0) / (values.length - 1);
  return Math.sqrt(Math.max(0, variance));
}

function groupByCharacteristic(samples) {
  const groups = new Map();
  for (const s of samples || []) {
    if (!s || typeof s !== "object") continue;
    const characteristic = String(s.characteristic || s.metric || "genel").trim() || "genel";
    const value = Number(s.value);
    if (!Number.isFinite(value)) continue;
    if (!groups.has(characteristic)) groups.set(characteristic, []);
    groups.get(characteristic).push({ ...s, value });
  }
  return groups;
}

function computeSpcSummary(samples) {
  const groups = groupByCharacteristic(samples);
  const summary = [];
  for (const [characteristic, list] of groups.entries()) {
    const values = list.map((x) => Number(x.value)).filter(Number.isFinite);
    if (values.length === 0) continue;
    const count = values.length;
    const mean = values.reduce((a, b) => a + b, 0) / count;
    const stdDev = computeStd(values, mean);
    const min = Math.min(...values);
    const max = Math.max(...values);

    const lslValues = list.map((x) => Number(x.lsl)).filter(Number.isFinite);
    const uslValues = list.map((x) => Number(x.usl)).filter(Number.isFinite);
    const lsl = lslValues.length > 0 ? lslValues[lslValues.length - 1] : null;
    const usl = uslValues.length > 0 ? uslValues[uslValues.length - 1] : null;

    let cp = null;
    let cpk = null;
    if (stdDev > 0 && Number.isFinite(lsl) && Number.isFinite(usl) && usl > lsl) {
      cp = (usl - lsl) / (6 * stdDev);
      const cpu = (usl - mean) / (3 * stdDev);
      const cpl = (mean - lsl) / (3 * stdDev);
      cpk = Math.min(cpu, cpl);
    }

    let outOfSpec = 0;
    if (Number.isFinite(lsl) || Number.isFinite(usl)) {
      outOfSpec = values.filter((v) => {
        if (Number.isFinite(lsl) && v < lsl) return true;
        if (Number.isFinite(usl) && v > usl) return true;
        return false;
      }).length;
    }

    summary.push({
      characteristic,
      count,
      mean: round(mean, 6),
      stdDev: round(stdDev, 6),
      min: round(min, 6),
      max: round(max, 6),
      lsl: Number.isFinite(lsl) ? lsl : null,
      usl: Number.isFinite(usl) ? usl : null,
      cp: cp === null ? null : round(cp, 4),
      cpk: cpk === null ? null : round(cpk, 4),
      outOfSpec,
      outOfSpecRate: round((outOfSpec / count) * 100, 3),
    });
  }

  summary.sort((a, b) => String(a.characteristic).localeCompare(String(b.characteristic), "tr"));
  return summary;
}

const APPROVAL_TYPES = {
  orderRevision: "order_revision",
  dueDateChange: "due_date_change",
  scrapApproval: "scrap_approval",
  shipmentApproval: "shipment_approval",
  invoiceApproval: "invoice_approval",
};

function detectApprovalRequirements(collection, currentItem, changes) {
  const c = String(collection || "");
  const curr = currentItem || {};
  const patch = changes || {};
  const required = [];

  const hasChanged = (field) => {
    if (!Object.prototype.hasOwnProperty.call(patch, field)) return false;
    return JSON.stringify(curr[field]) !== JSON.stringify(patch[field]);
  };

  const anyChanged = (fields) => fields.some((f) => hasChanged(f));

  if (c === "orders") {
    if (anyChanged(["revision", "revisionNo", "revNo", "revisionReason", "items"])) {
      required.push(APPROVAL_TYPES.orderRevision);
    }
    if (anyChanged(["deliveryDate", "dueDate", "termin", "terminDate"])) {
      required.push(APPROVAL_TYPES.dueDateChange);
    }
    if (hasChanged("status")) {
      const nextStatus = String(patch.status || "").toLowerCase();
      if (["shipped", "dispatched", "delivered"].includes(nextStatus)) {
        required.push(APPROVAL_TYPES.shipmentApproval);
      }
    }
  }

  if (c === "workOrders" || c === "productionJobs") {
    if (anyChanged(["rejectQty", "scrapQty", "fireQty", "rejectReason", "scrapReason", "scrapInfo"])) {
      required.push(APPROVAL_TYPES.scrapApproval);
    }
    if (hasChanged("status")) {
      const nextStatus = String(patch.status || "").toLowerCase();
      if (["shipped", "dispatched", "delivered"].includes(nextStatus)) {
        required.push(APPROVAL_TYPES.shipmentApproval);
      }
    }
  }

  if (c === "invoices") {
    if (hasChanged("status")) {
      const nextStatus = String(patch.status || "").toLowerCase();
      if (["sent", "paid", "cancelled"].includes(nextStatus)) {
        required.push(APPROVAL_TYPES.invoiceApproval);
      }
    }
  }

  return [...new Set(required)];
}

module.exports = {
  APPROVAL_TYPES,
  detectApprovalRequirements,
  computeSpcSummary,
};
