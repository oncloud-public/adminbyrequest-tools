// Is the person who clicked in the customer's approver group? (Microsoft Graph, app permissions
// User.ReadBasic.All + GroupMember.Read.All on the app's managed identity. Nested groups count.)
const { credential } = require('./azure')

const cache = new Map() // `${oid}|${gid}` -> { ok, until }

async function isMember (userOid, groupId) {
  if (!userOid || !groupId) return false
  const k = `${userOid}|${groupId}`
  const hit = cache.get(k)
  if (hit && hit.until > Date.now()) return hit.ok

  const { token } = await credential.getToken('https://graph.microsoft.com/.default')
  const res = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(userOid)}/checkMemberGroups`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ groupIds: [groupId] }),
    signal: AbortSignal.timeout(15000)
  })
  if (!res.ok) throw new Error(`Graph group check returned ${res.status}`)
  const ok = ((await res.json()).value || []).includes(groupId)
  cache.set(k, { ok, until: Date.now() + 2 * 60 * 1000 }) // short cache: removals apply within 2 minutes
  return ok
}

async function graphGet (url) {
  const { token } = await credential.getToken('https://graph.microsoft.com/.default')
  const res = await fetch(`https://graph.microsoft.com/v1.0${url}`, {
    headers: { Authorization: `Bearer ${token}`, ConsistencyLevel: 'eventual' }, signal: AbortSignal.timeout(15000)
  })
  if (!res.ok) throw new Error(`Graph returned ${res.status}`)
  return res.json()
}

// Security groups for the approver picker (needs GroupMember.Read.All).
async function searchGroups (q) {
  const query = q
    ? `&$search=${encodeURIComponent(`"displayName:${q.replace(/"/g, '')}"`)}`
    : '&$orderby=displayName'
  const r = await graphGet(`/groups?$select=id,displayName&$top=100&$count=true&$filter=securityEnabled eq true${query}`)
  return (r.value || []).map(g => ({ id: g.id, name: g.displayName })).sort((a, b) => a.name.localeCompare(b.name))
}

const getGroup = (id) => graphGet(`/groups/${encodeURIComponent(id)}?$select=id,displayName`)

module.exports = { isMember, searchGroups, getGroup }
