// ABR approvals bot: posts Admin By Request requests of many customers (ABR tenants) to Teams channels,
// and lets approvers approve or deny on the card. The card then updates for everyone.
const {
  AgentApplication, MemoryStorage, CloudAdapter, loadAuthConfigFromEnv, AdaptiveCardActionExecuteResponseType
} = require('@microsoft/agents-hosting')
const { startServer } = require('@microsoft/agents-hosting-express')
const { TeamsInfo } = require('@microsoft/agents-hosting-extensions-teams')
const store = require('./azure')
const abr = require('./abr')
const cards = require('./cards')
const graph = require('./graph')
const poller = require('./poller')
const admin = require('./admin')
const teamsPackage = require('./teamsPackage')

const authConfig = loadAuthConfigFromEnv()
const adapter = new CloudAdapter(authConfig)
const app = new AgentApplication({
  storage: new MemoryStorage(),
  adapter,
  adaptiveCardsOptions: { actionExecuteResponseType: AdaptiveCardActionExecuteResponseType.REPLACE_FOR_ALL }
})

function log (...a) { console.log(new Date().toISOString(), ...a) }

// --- Remember every channel of a team the app is in, so the Customers tab can link customers to channels ---
async function registerTeamChannels (ctx) {
  const cd = ctx.activity.channelData || {}
  if (!cd.team || !cd.team.id) return 0
  const ref = ctx.activity.getConversationReference()
  delete ref.activityId
  let teamName = cd.team.name || ''
  if (!teamName) { try { teamName = (await TeamsInfo.getTeamDetails(ctx, cd.team.id)).name || '' } catch { } }
  // Teams lists only the channels the app was added to; also keep the channel this activity came from.
  const channels = await TeamsInfo.getTeamChannels(ctx, cd.team.id).catch(() => [])
  if (cd.channel && cd.channel.id && !channels.some(c => c.id === cd.channel.id)) {
    channels.push({ id: cd.channel.id, name: cd.channel.name })
  }
  for (const ch of channels) {
    const old = ch.name ? null : await store.getChannel(ch.id)
    await store.saveChannel({
      channelId: ch.id,
      channelName: ch.name || (old && old.channelName !== 'General' ? old.channelName : '') || 'General',
      teamId: cd.team.id,
      teamName,
      reference: JSON.stringify({ ...ref, conversation: { ...ref.conversation, id: ch.id } }),
      savedUtc: new Date().toISOString()
    })
  }
  return channels.length
}

app.onActivity('conversationUpdate', async (ctx) => {
  try {
    const n = await registerTeamChannels(ctx)
    const added = (ctx.activity.membersAdded || []).some(m => m.id === ctx.activity.recipient.id)
    if (added && n) {
      log(`installed in team '${ctx.activity.channelData.team.name}', ${n} channel(s) saved`)
      await ctx.sendActivity("ABR Approvals is installed. To send a customer's requests to a channel of this team, open the app's Customers tab, add the customer and pick the channel. @mention me once in any other channel you want to use.")
    }
  } catch (e) { log('conversationUpdate failed:', e.message) }
})

app.onActivity('message', async (ctx) => {
  try { await registerTeamChannels(ctx) } catch (e) { log('channel refresh failed:', e.message) }
  await ctx.sendActivity("I post Admin By Request requests here and handle Approve / Deny on the cards. Channels of this team are registered; link a customer to one in the app's Customers tab.")
})

// --- Approve / Deny ---
app.adaptiveCards.actionExecute(['approve', 'deny'], async (ctx, state, data) => {
  const verb = ctx.activity.value && ctx.activity.value.action && ctx.activity.value.action.verb
  const d = data.data || data
  const who = ctx.activity.from || {}
  const byName = who.name || 'unknown'
  try {
    if (process.env.TENANT_ID && ctx.activity.conversation.tenantId !== process.env.TENANT_ID) {
      return 'This app only accepts approvals from its own organization.'
    }
    const customer = await store.getCustomer(d.c)
    if (!customer) return 'This customer is no longer configured.'

    if (!(await graph.isMember(who.aadObjectId, customer.approverGroupId))) {
      await store.addDecision(customer.rowKey, d.id, { decision: verb, result: 'not-allowed', byName, byOid: who.aadObjectId || '' })
      log(`[${customer.rowKey}] ${byName} tried to ${verb} ${d.id}: not in the approver group`)
      return `You're not in the approver group for ${customer.name} (${customer.approverGroupName || customer.approverGroupId}).`
    }

    const rowKey = d.k || d.id // cards posted before keys had id + time carry only the id
    const posted = await store.getPosted(customer.rowKey, rowKey)
    const apiKey = await store.getAbrKey(customer)
    let pending = await abr.getPendingRequest(customer.region, apiKey, d.id)
    // ABR reuses ids: never let an old card approve a newer request with the same id.
    if (pending && cards.requestKey(pending) !== rowKey) pending = null
    const s = pending ? cards.snapshot(pending) : JSON.parse((posted && posted.snapshot) || '{}')

    if (!pending) {
      await store.savePosted({ partitionKey: customer.rowKey, rowKey, status: 'done', outcome: 'elsewhere' })
      return cards.resultCard(customer.name, s, 'elsewhere')
    }

    const reason = verb === 'deny' ? String(d.denyReason || '').trim().slice(0, 300) : ''
    if (verb === 'approve') await abr.approve(customer.region, apiKey, d.id)
    else await abr.deny(customer.region, apiKey, d.id, reason)

    await store.addDecision(customer.rowKey, d.id, {
      decision: verb, result: 'ok', reason, byName, byOid: who.aadObjectId || '',
      user: s.user, computer: s.computer, app: s.app, file: s.file, settingsName: s.settingsName
    })
    await store.savePosted({ partitionKey: customer.rowKey, rowKey, status: 'done', outcome: verb, byName })
    log(`[${customer.rowKey}] ${verb} ${d.id} by ${byName}`)
    return cards.resultCard(customer.name, s, verb, byName, reason)
  } catch (e) {
    log(`[${d.c}] ${verb} ${d.id} by ${byName} failed: ${e.message}`)
    try { await store.addDecision(d.c, d.id, { decision: verb, result: 'error', error: e.message.slice(0, 500), byName, byOid: who.aadObjectId || '' }) } catch { }
    return `Couldn't ${verb} the request: ${e.message}`
  }
})

// --- Start ---
startServer(app, {
  authConfig,
  beforeListen: (server) => {
    server.get('/health', (req, res) => res.json({ ok: true }))
    admin.mount(server)
    teamsPackage.mount(server)
  }
})
store.ensureTables()
  .then(() => poller.start(adapter, authConfig.clientId))
  .catch(e => log('startup failed (tables):', e.message))
