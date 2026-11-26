// Customers tab: the page (served inside Teams) and its API.
// Sign-in is Teams SSO: the tab gets a token for our Entra app (TAB_APP_ID) and sends it as a Bearer token.
// Only members of ADMIN_GROUP_ID may use the API. ABR keys go straight to Key Vault and are never returned.
const path = require('path')
const express = require('express')
const { createRemoteJWKSet, jwtVerify } = require('jose')
const store = require('./azure')
const graph = require('./graph')

const TENANT = process.env.TENANT_ID
const TAB_APP_ID = process.env.TAB_APP_ID
const ADMIN_GROUP_ID = process.env.ADMIN_GROUP_ID
const REGIONS = ['dc1', 'dc2', 'dc3', 'dc4', 'dc5', 'dc6']

const jwks = createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${TENANT}/discovery/v2.0/keys`))

function log (...a) { console.log(new Date().toISOString(), '[admin]', ...a) }

// --- auth: valid Teams SSO token from our tenant, and member of the admin group ---
async function requireAdmin (req, res, next) {
  try {
    if (!TAB_APP_ID || !ADMIN_GROUP_ID) return res.status(503).json({ error: 'The Customers tab is not configured (TAB_APP_ID / ADMIN_GROUP_ID).' })
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '')
    if (!m) return res.status(401).json({ error: 'Not signed in.' })
    const { payload } = await jwtVerify(m[1], jwks, {
      audience: [TAB_APP_ID, `api://${req.hostname}/${TAB_APP_ID}`],
      issuer: [`https://login.microsoftonline.com/${TENANT}/v2.0`, `https://sts.windows.net/${TENANT}/`]
    })
    if (payload.tid !== TENANT) return res.status(403).json({ error: 'Wrong organization.' })
    if (!(await graph.isMember(payload.oid, ADMIN_GROUP_ID))) {
      return res.status(403).json({ error: 'You are not in the admin group for ABR Approvals.' })
    }
    req.user = { oid: payload.oid, name: payload.name || payload.preferred_username || 'unknown' }
    next()
  } catch (e) {
    log('auth failed:', e.code || '', e.message)
    res.status(401).json({ error: 'Sign-in could not be verified.' })
  }
}

// --- ABR key check: find the region the key works in ---
async function detectRegion (apiKey) {
  for (const dc of REGIONS) {
    try {
      const r = await fetch(`https://${dc}api.adminbyrequest.com/requests?status=pending`, {
        headers: { apikey: apiKey, Accept: 'application/json' }, signal: AbortSignal.timeout(15000)
      })
      if (r.ok) return dc
    } catch { }
  }
  return null
}

const slug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50)
const clean = (s, max = 100) => String(s || '').replace(/[\u0000-\u001f]/g, '').trim().slice(0, max)
const isGuid = (s) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(s || ''))

function customerView (c, channels) {
  const ch = channels.find(x => x.channelId === c.channelId)
  return {
    id: c.rowKey, name: c.name, region: c.region, enabled: c.enabled !== false,
    channelId: c.channelId || '', channel: ch ? `${ch.teamName} / ${ch.channelName}` : '(channel not found)',
    approverGroupId: c.approverGroupId || '', approverGroupName: c.approverGroupName || '',
    lastPollUtc: c.lastPollUtc || '', lastError: c.lastError || '', pending: c.pending ?? null
  }
}

function mount (server) {
  // The page and its script (also the Teams JS library, served from our own host)
  const pub = path.join(__dirname, '..', 'public')
  const frame = (req, res, next) => {
    res.set('Content-Security-Policy', "frame-ancestors 'self' https://teams.microsoft.com https://*.teams.microsoft.com https://*.cloud.microsoft https://*.office.com https://*.microsoft365.com")
    res.set('X-Content-Type-Options', 'nosniff')
    next()
  }
  server.get('/tab', frame, (req, res) => res.sendFile(path.join(pub, 'tab.html')))
  server.get('/tab/tab.js', frame, (req, res) => res.sendFile(path.join(pub, 'tab.js')))
  server.get('/tab/teams.js', frame, (req, res) =>
    res.sendFile(require.resolve('@microsoft/teams-js/dist/umd/MicrosoftTeams.min.js')))

  const api = express.Router()
  api.use(express.json({ limit: '20kb' }))
  api.use(requireAdmin)

  api.get('/state', async (req, res) => {
    const [customers, channels] = await Promise.all([store.listAllCustomers(), store.listChannels()])
    res.json({
      me: req.user.name,
      customers: customers.map(c => customerView(c, channels)).sort((a, b) => a.name.localeCompare(b.name)),
      channels: channels.map(c => ({ id: c.channelId, name: `${c.teamName} / ${c.channelName}` })).sort((a, b) => a.name.localeCompare(b.name))
    })
  })

  api.get('/groups', async (req, res) => {
    res.json(await graph.searchGroups(clean(req.query.q, 60)))
  })

  // Add or update. Key is optional on update (keeps the stored key).
  api.post('/customers', async (req, res) => {
    const b = req.body || {}
    const name = clean(b.name, 60)
    const id = b.id ? slug(b.id) : slug(name)
    if (!name || !id) return res.status(400).json({ error: 'Customer name is required.' })
    if (!b.channelId) return res.status(400).json({ error: 'Pick a channel.' })
    if (!isGuid(b.approverGroupId)) return res.status(400).json({ error: 'Pick an approver group.' })
    if (!(await store.getChannel(b.channelId))) return res.status(400).json({ error: 'That channel is not registered.' })

    const existing = await store.getCustomer(id)
    if (!b.id && existing) return res.status(409).json({ error: `A customer with the id "${id}" already exists.` })
    const apiKey = String(b.apiKey || '').trim()
    if (!existing && !apiKey) return res.status(400).json({ error: 'The ABR API key is required for a new customer.' })

    let region = existing && existing.region
    let keySecret = (existing && existing.keySecret) || `abr-key-${id}`
    if (apiKey) {
      if (apiKey.length > 200) return res.status(400).json({ error: 'That does not look like an ABR API key.' })
      region = await detectRegion(apiKey)
      if (!region) return res.status(400).json({ error: 'The key did not work in any ABR region. Check the key and that the API is enabled in ABR.' })
      keySecret = `abr-key-${id}`
      await store.setAbrKey(keySecret, apiKey)
    }
    const group = await graph.getGroup(b.approverGroupId)
    await store.saveCustomer({
      rowKey: id, name, region, channelId: b.channelId, keySecret,
      approverGroupId: group.id, approverGroupName: group.displayName,
      enabled: existing ? existing.enabled !== false : true,
      updatedBy: req.user.name, updatedUtc: new Date().toISOString()
    })
    log(`${existing ? 'updated' : 'added'} customer ${id} (region ${region}) by ${req.user.name}${apiKey ? ', key replaced' : ''}`)
    res.json({ ok: true, id, region })
  })

  api.post('/customers/:id/test', async (req, res) => {
    const c = await store.getCustomer(slug(req.params.id))
    if (!c) return res.status(404).json({ error: 'No such customer.' })
    const key = await store.getAbrKey(c)
    const region = await detectRegion(key)
    res.json({ ok: Boolean(region), region, message: region ? `Key works (region ${region}).` : 'The key does not work any more.' })
  })

  api.post('/customers/:id/enabled', async (req, res) => {
    const c = await store.getCustomer(slug(req.params.id))
    if (!c) return res.status(404).json({ error: 'No such customer.' })
    await store.saveCustomer({ rowKey: c.rowKey, enabled: Boolean(req.body && req.body.enabled), updatedBy: req.user.name, updatedUtc: new Date().toISOString() })
    log(`customer ${c.rowKey} ${req.body.enabled ? 'enabled' : 'paused'} by ${req.user.name}`)
    res.json({ ok: true })
  })

  api.delete('/customers/:id', async (req, res) => {
    const c = await store.getCustomer(slug(req.params.id))
    if (!c) return res.status(404).json({ error: 'No such customer.' })
    await store.deleteCustomer(c.rowKey)
    // Delete the key only if it belongs to this customer alone (recoverable in Key Vault for 7 days).
    const others = (await store.listAllCustomers()).some(x => x.keySecret === c.keySecret)
    if (c.keySecret && c.keySecret.startsWith('abr-key-') && !others) await store.deleteAbrKey(c.keySecret)
    log(`removed customer ${c.rowKey} by ${req.user.name}`)
    res.json({ ok: true })
  })

  api.use((err, req, res, next) => { log('error:', err.message); res.status(500).json({ error: 'Something went wrong. Try again.' }) })
  server.use('/api/admin', api)
}

module.exports = { mount }
