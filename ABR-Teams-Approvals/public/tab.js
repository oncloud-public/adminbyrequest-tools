/* global microsoftTeams */
// Customers tab: Teams SSO token -> /api/admin. No keys are ever shown or read back.
(function () {
  const $ = (id) => document.getElementById(id)
  let token = null
  let state = { customers: [], channels: [] }
  let editing = null // customer id being edited, or null for a new one

  // --- Teams context, theme, SSO ---
  async function initTeams () {
    await microsoftTeams.app.initialize()
    const ctx = await microsoftTeams.app.getContext()
    setTheme(ctx.app && ctx.app.theme)
    microsoftTeams.app.registerOnThemeChangeHandler(setTheme)
  }
  function setTheme (t) { document.documentElement.dataset.theme = t === 'dark' ? 'dark' : t === 'contrast' ? 'contrast' : 'light' }

  async function getToken (force) {
    if (!token || force) token = await microsoftTeams.authentication.getAuthToken()
    return token
  }

  async function api (method, url, body) {
    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await fetch('/api/admin' + url, {
        method,
        headers: { Authorization: 'Bearer ' + await getToken(attempt > 0), 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined
      })
      if (res.status === 401 && attempt === 0) continue
      const data = await res.json().catch(() => ({}))
      if (!res.ok) { const e = new Error(data.error || `Request failed (${res.status})`); e.status = res.status; throw e }
      return data
    }
  }

  // --- messages ---
  let msgTimer
  function say (text, kind) {
    const m = $('msg')
    m.textContent = text
    m.className = 'msg ' + (kind || '')
    m.hidden = false
    clearTimeout(msgTimer)
    if (kind !== 'bad') msgTimer = setTimeout(() => { m.hidden = true }, 6000)
  }

  // --- list ---
  function ago (iso) {
    if (!iso) return ''
    const s = Math.round((Date.now() - Date.parse(iso)) / 1000)
    if (s < 90) return 'just now'
    if (s < 3600) return Math.round(s / 60) + ' min ago'
    if (s < 86400) return Math.round(s / 3600) + ' h ago'
    return new Date(iso).toLocaleDateString()
  }

  function statusOf (c) {
    if (!c.enabled) return { cls: 'warn', text: 'Paused' }
    if (c.lastError) {
      const e = c.lastError
      const text = /returned (401|403)/.test(e) ? 'ABR rejected the key: create a new one and use Edit'
        : /timeout|fetch failed|ENOTFOUND|ECONN/i.test(e) ? 'Could not reach ABR, will retry'
          : 'Error: ' + e
      return { cls: 'bad', text }
    }
    if (!c.lastPollUtc) return { cls: '', text: 'Waiting for first check' }
    const p = c.pending > 0 ? `${c.pending} pending · ` : ''
    return { cls: 'ok', text: `OK · ${p}checked ${ago(c.lastPollUtc)}` }
  }

  function el (tag, props, ...kids) {
    const e = document.createElement(tag)
    Object.assign(e, props || {})
    for (const k of kids) if (k != null) e.append(k)
    return e
  }

  function render () {
    const rows = $('rows')
    rows.replaceChildren()
    $('count').textContent = state.customers.length ? `${state.customers.length}` : ''
    $('empty').hidden = state.customers.length > 0
    for (const c of state.customers) {
      const st = statusOf(c)
      const actions = el('div', { className: 'actions' },
        el('button', { textContent: 'Edit', onclick: () => openForm(c) }),
        el('button', { textContent: 'Test key', onclick: (e) => testKey(c, e.target) }),
        el('button', { textContent: c.enabled ? 'Pause' : 'Resume', onclick: () => setEnabled(c, !c.enabled) }),
        el('button', { textContent: 'Remove', className: 'danger', onclick: (e) => remove(c, e.currentTarget) }))
      rows.append(el('tr', {},
        el('td', { className: 'name' }, c.name, el('div', { className: 'sub', textContent: `${c.id} · ${c.region || '?'}` })),
        el('td', { textContent: c.channel }),
        el('td', { textContent: c.approverGroupName || c.approverGroupId }),
        el('td', {}, el('span', { className: 'status' }, el('span', { className: 'dot ' + st.cls }), el('span', { textContent: st.text }))),
        el('td', { className: 'act' }, actions)))
    }
  }

  async function load () {
    state = await api('GET', '/state')
    render()
  }

  // --- form ---
  function fillChannels (selected) {
    const s = $('fChannel')
    s.replaceChildren(el('option', { value: '', textContent: 'Pick a channel' }))
    for (const ch of state.channels) s.append(el('option', { value: ch.id, textContent: ch.name, selected: ch.id === selected }))
  }

  let groupTimer
  async function searchGroups (q, keep) {
    const s = $('fGroup')
    try {
      const groups = await api('GET', '/groups?q=' + encodeURIComponent(q || ''))
      const current = keep && !groups.some(g => g.id === keep.id) ? [keep] : []
      s.replaceChildren(el('option', { value: '', textContent: groups.length || current.length ? 'Pick a group' : 'No groups found' }))
      for (const g of current.concat(groups)) s.append(el('option', { value: g.id, textContent: g.name, selected: keep && g.id === keep.id }))
    } catch (e) { say(e.message, 'bad') }
  }

  function openForm (c) {
    editing = c ? c.id : null
    $('formTitle').textContent = c ? `Edit ${c.name}` : 'Add customer'
    $('fName').value = c ? c.name : ''
    $('fKey').value = ''
    $('fKey').required = !c
    $('fKey').placeholder = c ? 'Leave empty to keep the current key' : 'Paste the key'
    $('fGroupSearch').value = ''
    fillChannels(c && c.channelId)
    searchGroups('', c && c.approverGroupId ? { id: c.approverGroupId, name: c.approverGroupName } : null)
    $('form').hidden = false
    $('add').hidden = true
    $('fName').focus()
  }

  function closeForm () {
    $('form').hidden = true
    $('add').hidden = false
    $('fKey').value = ''
    editing = null
  }

  async function save (ev) {
    ev.preventDefault()
    const btn = $('save')
    const body = {
      id: editing || undefined,
      name: $('fName').value.trim(),
      apiKey: $('fKey').value.trim() || undefined,
      channelId: $('fChannel').value,
      approverGroupId: $('fGroup').value
    }
    btn.disabled = true
    btn.textContent = body.apiKey ? 'Checking key…' : 'Saving…'
    try {
      const r = await api('POST', '/customers', body)
      $('fKey').value = ''
      closeForm()
      say(`Saved ${body.name}${body.apiKey ? ` (key works, region ${r.region})` : ''}. New requests show up within a minute.`, 'ok')
      await load()
    } catch (e) { say(e.message, 'bad') } finally { btn.disabled = false; btn.textContent = 'Save' }
  }

  // --- row actions ---
  async function testKey (c, btn) {
    btn.disabled = true; btn.textContent = 'Testing…'
    try { const r = await api('POST', `/customers/${encodeURIComponent(c.id)}/test`); say(`${c.name}: ${r.message}`, r.ok ? 'ok' : 'bad') } catch (e) { say(e.message, 'bad') } finally { btn.disabled = false; btn.textContent = 'Test key' }
  }

  async function setEnabled (c, enabled) {
    try { await api('POST', `/customers/${encodeURIComponent(c.id)}/enabled`, { enabled }); say(`${c.name} ${enabled ? 'resumed' : 'paused: its requests are not posted'}.`, 'ok'); await load() } catch (e) { say(e.message, 'bad') }
  }

  // Teams blocks window.confirm in tabs, so removing takes a second click within 5 seconds.
  async function remove (c, btn) {
    if (btn.dataset.armed !== '1') {
      btn.dataset.armed = '1'
      btn.textContent = 'Click again to remove'
      say(`Remove ${c.name}? Its requests stop showing in Teams, and its API key is deleted from Key Vault (recoverable for 7 days). Click the button again to confirm.`)
      setTimeout(() => { if (btn.isConnected) { btn.dataset.armed = ''; btn.textContent = 'Remove' } }, 5000)
      return
    }
    btn.disabled = true; btn.textContent = 'Removing…'
    try { await api('DELETE', `/customers/${encodeURIComponent(c.id)}`); say(`${c.name} removed.`, 'ok'); await load() } catch (e) { say(e.message, 'bad'); btn.disabled = false; btn.textContent = 'Remove'; btn.dataset.armed = '' }
  }

  // --- start ---
  function blocked (text) {
    $('loading').hidden = true
    $('app').hidden = true
    const b = $('blocked'); b.textContent = text; b.hidden = false
  }

  async function start () {
    try { await initTeams() } catch { return blocked('Open this page from the ABR Approvals app in Microsoft Teams.') }
    try {
      await load()
      $('loading').hidden = true
      $('app').hidden = false
    } catch (e) {
      return blocked(e.status === 403 ? e.message + ' Ask an admin to add you.' : 'Could not load customers: ' + e.message)
    }
    $('add').onclick = () => openForm(null)
    $('cancel').onclick = closeForm
    $('form').onsubmit = save
    $('fGroupSearch').oninput = (e) => { clearTimeout(groupTimer); groupTimer = setTimeout(() => searchGroups(e.target.value.trim()), 300) }
    setInterval(() => { if ($('form').hidden) load().catch(() => {}) }, 60000)
  }
  start()
})()
