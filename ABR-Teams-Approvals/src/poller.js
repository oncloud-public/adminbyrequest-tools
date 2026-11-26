// Every minute: for every customer, read pending ABR requests and post new ones to the customer's channel.
// Also closes cards whose request was handled outside Teams (ABR portal or app).
const { MessageFactory, CardFactory } = require('@microsoft/agents-hosting')
const store = require('./azure')
const abr = require('./abr')
const cards = require('./cards')

const INTERVAL_MS = Number(process.env.POLL_SECONDS || 60) * 1000
const PARALLEL = 5
const PAGE_GUARD = 50 // if ABR returns this many or more, it may be a partial list: don't close cards from it

function log (...a) { console.log(new Date().toISOString(), ...a) }

// Nothing in a poll round may hang forever: a stuck call would block every later round.
function withTimeout (promise, ms, what) {
  let t
  return Promise.race([promise, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`timeout after ${ms / 1000}s: ${what}`)), ms) })])
    .finally(() => clearTimeout(t))
}
const DEBUG = process.env.POLL_DEBUG === 'true'
const dbg = (...a) => { if (DEBUG) log(...a) }

async function postCard (adapter, appId, channel, card) {
  const ref = JSON.parse(channel.reference)
  let activityId = null
  await adapter.continueConversation(appId, ref, async (ctx) => {
    const res = await ctx.sendActivity(MessageFactory.attachment(CardFactory.adaptiveCard(card)))
    activityId = res && res.id
  })
  return activityId
}

async function updateCard (adapter, appId, channel, activityId, card) {
  const ref = JSON.parse(channel.reference)
  await adapter.continueConversation(appId, ref, async (ctx) => {
    const act = MessageFactory.attachment(CardFactory.adaptiveCard(card))
    act.id = activityId
    await ctx.updateActivity(act)
  })
}

async function pollCustomer (adapter, appId, customer) {
  dbg(`[${customer.rowKey}] reading key`)
  const apiKey = await withTimeout(store.getAbrKey(customer), 20000, 'Key Vault')
  dbg(`[${customer.rowKey}] reading pending requests`)
  const pending = await abr.getPending(customer.region, apiKey)
  dbg(`[${customer.rowKey}] ${pending.length} pending: ${pending.map(r => `${r.id}@${r.requestTime}`).join(", ")}`)
  const pendingKeys = new Set(pending.map(cards.requestKey))

  if (pending.length) {
    const channel = customer.channelId ? await store.getChannel(customer.channelId) : null
    if (!channel) {
      log(`[${customer.rowKey}] ${pending.length} pending, but no channel is linked (pick one for this customer in the Customers tab).`)
    } else {
      for (const r of pending) {
        const k = cards.requestKey(r)
        if (!r.id || await store.getPosted(customer.rowKey, k)) continue
        const s = cards.snapshot(r)
        dbg(`[${customer.rowKey}] posting ${r.id}`)
        const activityId = await withTimeout(postCard(adapter, appId, channel, cards.requestCard(customer, r, s)), 30000, 'post card')
        await store.savePosted({
          partitionKey: customer.rowKey, rowKey: k, requestId: String(r.id), status: 'open',
          channelId: customer.channelId, activityId, snapshot: JSON.stringify(s), postedUtc: new Date().toISOString()
        })
        log(`[${customer.rowKey}] posted request ${r.id} (${s.settingsName})`)
      }
    }
  }

  // Close cards handled elsewhere. Only on a full, successful read, and not for cards just posted.
  if (pending.length < PAGE_GUARD) {
    for (const p of await store.listOpen(customer.rowKey)) {
      if (pendingKeys.has(String(p.rowKey))) continue
      if (Date.now() - Date.parse(p.postedUtc || 0) < 2 * 60 * 1000) continue
      const channel = await store.getChannel(p.channelId)
      if (channel && p.activityId) {
        dbg(`[${customer.rowKey}] closing ${p.rowKey}`)
        await withTimeout(updateCard(adapter, appId, channel, p.activityId,
          cards.resultCard(customer.name, JSON.parse(p.snapshot || '{}'), 'elsewhere')), 30000, 'update card')
      }
      await store.savePosted({ partitionKey: customer.rowKey, rowKey: p.rowKey, status: 'done', outcome: 'elsewhere' })
      log(`[${customer.rowKey}] request ${p.rowKey} handled outside Teams, card closed`)
    }
  }
  return pending.length
}

const lastStatus = new Map()
async function recordStatus (c, pending, error) {
  const sig = `${pending}|${error || ''}`
  const prev = lastStatus.get(c.rowKey)
  if (prev && prev.sig === sig && Date.now() - prev.at < 2 * 60 * 1000) return
  lastStatus.set(c.rowKey, { sig, at: Date.now() })
  try {
    await store.saveCustomer({ rowKey: c.rowKey, lastPollUtc: new Date().toISOString(), pending: pending ?? -1, lastError: (error || '').slice(0, 300) })
  } catch (e) { log(`[${c.rowKey}] could not save status: ${e.message}`) }
}

let running = false
async function tick (adapter, appId) {
  if (running) return
  running = true
  const started = Date.now()
  try {
    dbg('round start')
    const customers = await withTimeout(store.listCustomers(), 20000, 'list customers')
    for (let i = 0; i < customers.length; i += PARALLEL) {
      await Promise.all(customers.slice(i, i + PARALLEL).map(c =>
        withTimeout(pollCustomer(adapter, appId, c), 50000, 'customer round')
          .then(n => recordStatus(c, n, ''))
          .catch(e => { log(`[${c.rowKey}] poll failed: ${e.message}`); return recordStatus(c, null, e.message) })))
    }
    dbg(`round done in ${Date.now() - started}ms, ${customers.length} customer(s)`)
  } catch (e) {
    log('poll round failed:', e.message)
  } finally {
    running = false
  }
}

function start (adapter, appId) {
  setTimeout(() => tick(adapter, appId), 10 * 1000)
  setInterval(() => tick(adapter, appId), INTERVAL_MS)
  log(`poller started, every ${INTERVAL_MS / 1000}s`)
}

module.exports = { start, updateCard }
