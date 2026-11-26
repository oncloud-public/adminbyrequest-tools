#!/usr/bin/env bash
# Second step after "Deploy to Azure": the Microsoft Entra part, which a template can't do reliably.
#   - Graph permissions for the bot (read-only: User.ReadBasic.All + GroupMember.Read.All)
#   - App registration for Teams sign-in to the Customers tab (no secret)
#   - Admin group "ABR Approvals Admins" with you in it
# Run in Azure Cloud Shell (Bash) as a Global Administrator (or Privileged Role Administrator + Application Administrator):
#   curl -sL https://raw.githubusercontent.com/oncloud-public/adminbyrequest-tools/main/ABR-Teams-Approvals/infra/setup-entra.sh | bash -s -- <resource group>
set -euo pipefail
RG="${1:?Usage: setup-entra.sh <resource group>}"
ADMIN_GROUP_NAME="${ADMIN_GROUP_NAME:-ABR Approvals Admins}"
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

say "Finding the ABR Approvals app in $RG"
SITE=$(az webapp list -g "$RG" --query "[?tags.app=='abr-approvals'] | [0].name" -o tsv)
[ -n "$SITE" ] || { echo "No ABR Approvals app found in resource group $RG."; exit 1; }
HOST=$(az webapp show -n "$SITE" -g "$RG" --query defaultHostName -o tsv | tr 'A-Z' 'a-z')
MI_CLIENT=$(az webapp config appsettings list -n "$SITE" -g "$RG" --query "[?name=='AZURE_CLIENT_ID'].value | [0]" -o tsv)
MI_PRINCIPAL=$(az ad sp show --id "$MI_CLIENT" --query id -o tsv)
ME=$(az ad signed-in-user show --query id -o tsv)
echo "App: https://$HOST"

say "1/3 Graph permissions for the bot (checks who may approve)"
GRAPH_APP=00000003-0000-0000-c000-000000000000
GRAPH_SP=$(az ad sp show --id "$GRAPH_APP" --query id -o tsv)
for ROLE in User.ReadBasic.All GroupMember.Read.All; do
  ROLE_ID=$(az ad sp show --id "$GRAPH_APP" --query "appRoles[?value=='$ROLE'].id | [0]" -o tsv)
  HAVE=$(az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/$MI_PRINCIPAL/appRoleAssignments" \
    --query "value[?appRoleId=='$ROLE_ID'] | length(@)" -o tsv)
  if [ "$HAVE" != "0" ]; then echo "  $ROLE: already granted"; continue; fi
  az rest --method post -o none --url "https://graph.microsoft.com/v1.0/servicePrincipals/$MI_PRINCIPAL/appRoleAssignments" \
    --headers "Content-Type=application/json" \
    --body "{\"principalId\":\"$MI_PRINCIPAL\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$ROLE_ID\"}"
  echo "  $ROLE: granted"
done

say "2/3 Teams sign-in for the Customers tab"
APP_NAME="ABR Approvals by OnCloud - Customers tab ($SITE)"
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)
[ -n "$APP_ID" ] || APP_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
OBJ=$(az ad app show --id "$APP_ID" --query id -o tsv)
az ad sp show --id "$APP_ID" -o none 2>/dev/null || az ad sp create --id "$APP_ID" -o none
SCOPE_ID=$(az ad app show --id "$APP_ID" --query "api.oauth2PermissionScopes[?value=='access_as_user'].id | [0]" -o tsv)
[ -n "$SCOPE_ID" ] || SCOPE_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
URL="https://graph.microsoft.com/v1.0/applications/$OBJ"
az rest --method patch --url "$URL" --headers "Content-Type=application/json" --body "{
  \"identifierUris\": [\"api://$HOST/$APP_ID\"],
  \"api\": { \"requestedAccessTokenVersion\": 2, \"oauth2PermissionScopes\": [{
    \"id\": \"$SCOPE_ID\", \"value\": \"access_as_user\", \"type\": \"User\", \"isEnabled\": true,
    \"adminConsentDisplayName\": \"Use the ABR Approvals Customers tab\",
    \"adminConsentDescription\": \"Lets Teams sign the user in to the ABR Approvals Customers tab.\",
    \"userConsentDisplayName\": \"Use the ABR Approvals Customers tab\",
    \"userConsentDescription\": \"Lets Teams sign you in to the ABR Approvals Customers tab.\" }] } }"
az rest --method patch --url "$URL" --headers "Content-Type=application/json" --body "{
  \"api\": { \"preAuthorizedApplications\": [
    { \"appId\": \"1fec8e78-bce4-4aaf-ab1b-5451cc387264\", \"delegatedPermissionIds\": [\"$SCOPE_ID\"] },
    { \"appId\": \"5e3ce6c0-2b1f-4285-8d4b-75ee78787346\", \"delegatedPermissionIds\": [\"$SCOPE_ID\"] } ] } }"
echo "  App registration: $APP_ID (no secret)"

say "3/3 Admin group: who may manage customers"
GID=$(az ad group list --display-name "$ADMIN_GROUP_NAME" --query "[0].id" -o tsv)
if [ -z "$GID" ]; then
  GID=$(az ad group create --display-name "$ADMIN_GROUP_NAME" --mail-nickname "abr-approvals-admins-$(date +%s)" \
    --description "Can manage customers in ABR Approvals by OnCloud" --query id -o tsv)
fi
[ "$(az ad group member check --group "$GID" --member-id "$ME" --query value -o tsv)" = "true" ] || az ad group member add --group "$GID" --member-id "$ME"
echo "  Group: $ADMIN_GROUP_NAME (you are a member)"

az webapp config appsettings set -n "$SITE" -g "$RG" -o none --settings TAB_APP_ID="$APP_ID" ADMIN_GROUP_ID="$GID"

say "Done. Next, in Microsoft Teams:"
cat <<EOF
  1. Download the Teams app:   https://$HOST/teams-app.zip
  2. Teams admin center > Teams apps > Manage apps > Upload new app > pick the zip.
  3. Add the app to the team that will get the approval cards, and @mention it once in each channel you'll use.
  4. Open the app from Apps > "ABR Approvals by OnCloud" > Customers tab, and add your first customer.
  Approvers are set per customer in the tab (any Entra security group).
EOF
