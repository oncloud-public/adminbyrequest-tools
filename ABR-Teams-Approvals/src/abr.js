// Admin By Request public API: https://<region>api.adminbyrequest.com (region dc1..dc6)
const base = (region) => `https://${region || 'dc1'}api.adminbyrequest.com`

async function call (region, apiKey, method, path) {
  const res = await fetch(base(region) + path, {
    method,
    headers: { apikey: apiKey, Accept: 'application/json' },
    signal: AbortSignal.timeout(30000)
  })
  if (!res.ok) {
    const text = (await res.text().catch(() => '')).slice(0, 200)
    throw new Error(`ABR ${method} ${path.split('?')[0]} returned ${res.status} ${text}`)
  }
  const text = await res.text()
  return text ? JSON.parse(text) : null
}

// The list can come back as an array or wrapped in an object.
function records (resp) {
  if (!resp) return []
  if (Array.isArray(resp)) return resp
  for (const v of Object.values(resp)) if (Array.isArray(v)) return v
  return [resp]
}

module.exports = {
  getPending: async (region, apiKey) => records(await call(region, apiKey, 'GET', '/requests?status=pending')),

  // ABR has no documented single-request GET: read the pending list and pick the id.
  getPendingRequest: async (region, apiKey, id) =>
    records(await call(region, apiKey, 'GET', '/requests?status=pending')).find(r => String(r.id) === String(id)) || null,

  approve: (region, apiKey, id) => call(region, apiKey, 'PUT', `/requests/${encodeURIComponent(id)}`),

  // DELETE with ?reason= denies the request (not in the public docs, tested working).
  deny: (region, apiKey, id, reason) =>
    call(region, apiKey, 'DELETE', `/requests/${encodeURIComponent(id)}` + (reason ? `?reason=${encodeURIComponent(reason)}` : ''))
}
