// The Teams app package, built on the fly from this deployment's settings: GET /teams-app.zip
// Contains only public ids (bot id, tab app id, host). Upload it in the Teams admin center.
const fs = require('fs')
const path = require('path')
const { zipSync, strToU8 } = require('fflate')

const VERSION = '1.1.0'
const icons = path.join(__dirname, '..', 'public', 'icons')

function manifest (host) {
  const botId = process.env.CONNECTIONS__SERVICE_CONNECTION__SETTINGS__CLIENTID
  const tabAppId = process.env.TAB_APP_ID
  const m = {
    $schema: 'https://developer.microsoft.com/json-schemas/teams/v1.25/MicrosoftTeams.schema.json',
    manifestVersion: '1.25',
    version: VERSION,
    id: process.env.TEAMS_APP_ID,
    developer: {
      name: 'OnCloud',
      websiteUrl: 'https://www.oncld.io',
      privacyUrl: 'https://www.oncld.io/privacy',
      termsOfUseUrl: 'https://www.oncld.io/terms'
    },
    name: { short: 'ABR Approvals by OnCloud', full: 'Approvals for Admin By Request, by OnCloud' },
    description: {
      short: 'Approve Admin By Request requests from many tenants in Teams.',
      full: 'For MSPs, resellers and organizations with several Admin By Request tenants. Posts each tenant\'s elevation requests to its Teams channel. Approvers approve or deny on the card, and the card updates for everyone with who decided and when.'
    },
    icons: { color: 'color.png', outline: 'outline.png' },
    accentColor: '#1D1B16',
    supportsChannelFeatures: 'tier1',
    bots: [{ botId, scopes: ['team'], isNotificationOnly: false, supportsFiles: false }],
    permissions: ['identity', 'messageTeamMembers'],
    validDomains: [host]
  }
  if (tabAppId) {
    m.staticTabs = [{ entityId: 'customers', name: 'Customers', contentUrl: `https://${host}/tab`, scopes: ['personal'] }]
    m.webApplicationInfo = { id: tabAppId, resource: `api://${host}/${tabAppId}` }
  }
  return m
}

function mount (server) {
  server.get('/teams-app.zip', (req, res) => {
    const host = (process.env.WEBSITE_HOSTNAME || req.hostname).toLowerCase()
    if (!process.env.TEAMS_APP_ID) return res.status(503).send('TEAMS_APP_ID is not set.')
    const zip = zipSync({
      'manifest.json': strToU8(JSON.stringify(manifest(host), null, 2)),
      'color.png': fs.readFileSync(path.join(icons, 'color.png')),
      'outline.png': fs.readFileSync(path.join(icons, 'outline.png'))
    })
    res.set('Content-Type', 'application/zip')
    res.set('Content-Disposition', 'attachment; filename="abr-approvals.zip"')
    res.send(Buffer.from(zip))
  })
}

module.exports = { mount, manifest }
