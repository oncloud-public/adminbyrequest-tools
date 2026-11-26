// Azure access: Key Vault (ABR keys) and Table storage (customers, channels, posted cards, decisions).
// In Azure the app's user-assigned managed identity is used (AZURE_CLIENT_ID); locally, your az login.
const { DefaultAzureCredential } = require('@azure/identity')
const { SecretClient } = require('@azure/keyvault-secrets')
const { TableClient } = require('@azure/data-tables')

const credential = new DefaultAzureCredential({ managedIdentityClientId: process.env.AZURE_CLIENT_ID })

const vault = new SecretClient(`https://${process.env.KEY_VAULT_NAME}.vault.azure.net`, credential)
const table = (name) => new TableClient(`https://${process.env.STORAGE_ACCOUNT}.table.core.windows.net`, name, credential)

const T = {
  customers: table('botcustomers'),
  channels: table('botchannels'),
  posted: table('botposted'),
  decisions: table('botdecisions')
}

// Table keys can't contain / \ # ? : base64url keeps Teams channel ids safe.
const key = (s) => Buffer.from(String(s)).toString('base64url')

async function all (client, filter) {
  const out = []
  for await (const e of client.listEntities(filter ? { queryOptions: { filter } } : undefined)) out.push(e)
  return out
}

async function get (client, pk, rk) {
  try { return await client.getEntity(pk, rk) } catch (e) { if (e.statusCode === 404) return null; throw e }
}

// --- ABR API keys (cached 5 minutes, so a changed key applies without a restart) ---
const keyCache = new Map()
async function getAbrKey (customer) {
  const name = customer.keySecret || `abr-key-${customer.rowKey}`
  const hit = keyCache.get(name)
  if (hit && hit.until > Date.now()) return hit.value
  const s = await vault.getSecret(name)
  keyCache.set(name, { value: s.value, until: Date.now() + 5 * 60 * 1000 })
  return s.value
}

module.exports = {
  credential,
  getAbrKey,

  // customers: PK 'c', RK = customer id. name, region, channelId, approverGroupId, approverGroupName, keySecret, enabled
  listCustomers: async () => (await all(T.customers, "PartitionKey eq 'c'")).filter(c => c.enabled !== false),
  listAllCustomers: () => all(T.customers, "PartitionKey eq 'c'"),
  getCustomer: (id) => get(T.customers, 'c', id),
  saveCustomer: (c) => T.customers.upsertEntity({ partitionKey: 'c', ...c }, 'Merge'),
  deleteCustomer: (id) => T.customers.deleteEntity('c', id),

  // ABR keys: written by the Customers tab, never read back to it
  setAbrKey: async (name, value) => { await vault.setSecret(name, value, { contentType: 'ABR API key' }); keyCache.delete(name) },
  deleteAbrKey: async (name) => { await vault.beginDeleteSecret(name); keyCache.delete(name) },

  // channels the app is installed in: PK 'ch', RK = key(channelId)
  saveChannel: (ch) => T.channels.upsertEntity({ partitionKey: 'ch', rowKey: key(ch.channelId), ...ch }, 'Replace'),
  getChannel: (channelId) => get(T.channels, 'ch', key(channelId)),
  listChannels: () => all(T.channels, "PartitionKey eq 'ch'"),

  // cards posted: PK = customer id, RK = ABR request id
  getPosted: (cid, rid) => get(T.posted, cid, String(rid)),
  savePosted: (e) => T.posted.upsertEntity({ ...e, partitionKey: e.partitionKey, rowKey: String(e.rowKey) }, 'Merge'),
  listOpen: (cid) => all(T.posted, `PartitionKey eq '${cid.replace(/'/g, "''")}' and status eq 'open'`),

  // who decided what: PK = customer id, RK = request id + time
  addDecision: (cid, rid, d) => T.decisions.createEntity({
    partitionKey: cid, rowKey: `${rid}-${new Date().toISOString().replace(/[-:.TZ]/g, '')}`, requestId: String(rid), ...d
  }),

  ensureTables: async () => {
    for (const c of Object.values(T)) {
      try { await c.createTable() } catch (e) { if (e.statusCode !== 409) throw e }
    }
  }
}
