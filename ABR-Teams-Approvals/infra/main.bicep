// ABR Approvals by OnCloud: everything in Azure, for the "Deploy to Azure" button.
// After this deployment, run the one-line Entra setup shown in the outputs (Graph permissions, Teams sign-in, admin group).
// No secrets are created: the bot runs with a user-assigned managed identity.

@description('Short name used in resource names.')
@maxLength(14)
param namePrefix string = 'abr-approvals'

@description('Azure region. Default: the resource group region.')
param location string = resourceGroup().location

@description('URL of the app package (zip with code and dependencies). Default: release v0.1.0 on GitHub. The app fetches it at every restart.')
param packageUrl string = 'https://github.com/oncloud-public/adminbyrequest-tools/releases/download/teams-approvals-v0.1.0/abr-approvals-bot.zip'

@description('App Service plan size. B1 is enough for hundreds of customers.')
@allowed([ 'B1', 'B2', 'S1', 'P0v3' ])
param sku string = 'B1'

var suffix = substring(uniqueString(resourceGroup().id), 0, 6)
var appName = '${namePrefix}-${suffix}'
var storageName = 'stabr${suffix}${substring(uniqueString(subscription().id, resourceGroup().id), 0, 6)}'
var vaultName = 'kv-abr-${suffix}'
var tags = { app: 'abr-approvals' }
var tenantId = subscription().tenantId
var roles = {
  kvSecretsOfficer: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
  tableDataContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${appName}'
  location: location
  tags: tags
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // the app uses its managed identity only
    supportsHttpsTrafficOnly: true
  }
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource tables 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = [for t in [ 'botcustomers', 'botchannels', 'botposted', 'botdecisions' ]: {
  parent: tableService
  name: t
}]

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

// The app reads and writes ABR keys (the Customers tab saves them) and its tables.
resource kvRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, identity.id, roles.kvSecretsOfficer)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvSecretsOfficer)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource tableRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, roles.tableDataContributor)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.tableDataContributor)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: 'asp-${appName}'
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: sku }
  properties: { reserved: true }
}

resource site 'Microsoft.Web/sites@2023-12-01' = {
  name: appName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'NODE|22-lts'
      appCommandLine: 'npm start'
      alwaysOn: true // the poller runs inside the app
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      healthCheckPath: '/health'
      appSettings: [
        { name: 'WEBSITE_RUN_FROM_PACKAGE', value: packageUrl } // fetched and mounted at every start (read-only)
        { name: 'CONNECTIONS__SERVICE_CONNECTION__SETTINGS__AUTHTYPE', value: 'UserManagedIdentity' }
        { name: 'CONNECTIONS__SERVICE_CONNECTION__SETTINGS__CLIENTID', value: identity.properties.clientId }
        { name: 'CONNECTIONS__SERVICE_CONNECTION__SETTINGS__TENANTID', value: tenantId }
        { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
        { name: 'TENANT_ID', value: tenantId }
        { name: 'KEY_VAULT_NAME', value: vault.name }
        { name: 'STORAGE_ACCOUNT', value: storage.name }
        { name: 'TEAMS_APP_ID', value: guid(resourceGroup().id, 'abr-approvals-teams-app') }
      ]
    }
  }
  dependsOn: [ kvRole, tableRole, tables ]
}

resource bot 'Microsoft.BotService/botServices@2022-09-15' = {
  name: 'bot-${appName}'
  location: 'global'
  tags: tags
  kind: 'azurebot'
  sku: { name: 'F0' }
  properties: {
    displayName: 'ABR Approvals by OnCloud'
    endpoint: 'https://${site.properties.defaultHostName}/api/messages'
    msaAppType: 'UserAssignedMSI'
    msaAppId: identity.properties.clientId
    msaAppTenantId: tenantId
    msaAppMSIResourceId: identity.id
  }
}

resource teams 'Microsoft.BotService/botServices/channels@2022-09-15' = {
  parent: bot
  name: 'MsTeamsChannel'
  location: 'global'
  properties: {
    channelName: 'MsTeamsChannel'
    properties: { isEnabled: true }
  }
}

output appUrl string = 'https://${site.properties.defaultHostName}'
output resourceGroup string = resourceGroup().name
output nextStep string = 'In Azure Cloud Shell (Bash) run: curl -sL https://raw.githubusercontent.com/oncloud-public/adminbyrequest-tools/main/ABR-Teams-Approvals/infra/setup-entra.sh | bash -s -- ${resourceGroup().name}'
