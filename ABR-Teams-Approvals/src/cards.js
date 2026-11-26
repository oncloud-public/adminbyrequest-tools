// Adaptive Cards (1.5, Action.Execute) for requests and their outcome.

const v = (x) => (x === null || x === undefined || String(x).trim() === '' ? '-' : String(x))

// Teams renders DATE()/TIME() in each viewer's own time zone and locale, so an MSP's
// technicians anywhere see their local time. Format must be strict RFC 3339 UTC.
const fmt = (d) => {
  const iso = d.toISOString().replace(/\.\d{3}Z$/, 'Z')
  return `{{DATE(${iso})}} {{TIME(${iso})}}`
}

// ABR returns requestTime in UTC, as ISO without a zone ("2026-11-26T21:47:45").
// Older/other formats ("11/26/2026 21:47:45", M/D/Y) are read as UTC too; anything else is shown as-is.
function localTime (s) {
  const t = String(s || '').trim()
  let m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/.exec(t)
  if (m) {
    const d = m[7] ? new Date(t) : new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)))
    return isNaN(d) ? v(s) : fmt(d)
  }
  m = /^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{1,2}):(\d{2})(?::(\d{2}))?$/.exec(t)
  if (m) return fmt(new Date(Date.UTC(+m[3], +m[1] - 1, +m[2], +m[4], +m[5], +(m[6] || 0))))
  return v(s)
}

// ABR reuses a request id when the same user asks for the same app again, so a request
// occurrence is identified by id + request time.
const requestKey = (r) => `${r.id}-${String(r.requestTime || '').replace(/[^0-9]/g, '')}`

// The fields we keep per request, so the card can still be drawn after ABR no longer lists it.
function snapshot (r) {
  const a = r.application || {}
  let scan = v(a.scanResult)
  if (a.threat) scan += ` (${a.threat})`
  return {
    user: r.user ? `${v(r.user.fullName)} (${v(r.user.account)})` : '-',
    computer: v(r.computer && r.computer.name),
    type: v(r.type),
    app: v([a.name, a.vendor].filter(Boolean).join(' / ')),
    file: v(a.file),
    scan,
    notClean: Boolean(a.threat) || /malicious|suspicious|infected|threat/i.test(String(a.scanResult || '')),
    settingsName: v(r.settingsName),
    reason: v(r.reason),
    requestTime: localTime(r.requestTime),
    auditlogLink: r.auditlogLink || ''
  }
}

function facts (customerName, s) {
  return [
    { title: 'Customer', value: v(customerName) },
    { title: 'User', value: s.user },
    { title: 'Device', value: s.computer },
    { title: 'Type', value: s.type },
    { title: 'App', value: s.app },
    { title: 'File', value: s.file },
    { title: 'Scan', value: s.scan },
    { title: 'Sub setting', value: s.settingsName },
    { title: 'Reason', value: s.reason },
    { title: 'Requested', value: s.requestTime }
  ]
}

const base = (body, actions) => ({
  type: 'AdaptiveCard',
  $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
  version: '1.5',
  body,
  ...(actions && actions.length ? { actions } : {})
})

const auditAction = (s) => s.auditlogLink ? [{ type: 'Action.OpenUrl', title: 'Open in Admin By Request', url: s.auditlogLink }] : []

function requestCard (customer, r, s) {
  const data = { c: customer.rowKey, id: String(r.id), k: requestKey(r) }
  return base([
    {
      type: 'TextBlock', size: 'Medium', weight: 'Bolder', wrap: true,
      text: s.notClean ? `⚠ ${customer.name}: request with a non-clean scan` : `${customer.name}: new Admin By Request request`,
      color: s.notClean ? 'Attention' : 'Default'
    },
    { type: 'FactSet', facts: facts(customer.name, s) },
    { type: 'Input.Text', id: 'denyReason', placeholder: 'Reason for denying (optional, the user sees it)', isMultiline: false, maxLength: 300 }
  ], [
    { type: 'Action.Execute', title: 'Approve', verb: 'approve', style: 'positive', data },
    { type: 'Action.Execute', title: 'Deny', verb: 'deny', style: 'destructive', data },
    ...auditAction(s)
  ])
}

// outcome: 'approve' | 'deny' | 'elsewhere'
function resultCard (customerName, s, outcome, byName, reason) {
  const when = fmt(new Date())
  const line = outcome === 'approve' ? `✅ Approved by ${byName} · ${when}`
    : outcome === 'deny' ? `⛔ Denied by ${byName} · ${when}${reason ? ` · Reason: ${reason}` : ''}`
      : `ℹ Handled outside Teams (in the Admin By Request portal or app)`
  return base([
    { type: 'TextBlock', size: 'Medium', weight: 'Bolder', wrap: true, text: `${customerName}: Admin By Request request` },
    { type: 'TextBlock', wrap: true, text: line, weight: 'Bolder', color: outcome === 'approve' ? 'Good' : outcome === 'deny' ? 'Attention' : 'Default' },
    { type: 'FactSet', facts: facts(customerName, s) }
  ], auditAction(s))
}

module.exports = { snapshot, requestCard, resultCard, requestKey }
