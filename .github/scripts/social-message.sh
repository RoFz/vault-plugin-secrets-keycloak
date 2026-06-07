#!/usr/bin/env bash
#
# Build a release-announcement message from a GitHub release body, surfacing the
# changes that actually create interest and dropping the noise.
#
# Selection: features first, then bug fixes, EXCLUDING pure dependency bumps
# ("bump X from Y to Z") which are noise for an announcement. Bullets are added
# newest-interest-first until the character budget is reached. If nothing notable
# remains (e.g. a deps-only release), it falls back to the product description.
#
# Env in:  TAG, BODY (release notes markdown), URL (release page).
# Args:    $1 = MAX char budget (URLs are weighted as 23, like Twitter).
#          $2 = "desc" to always include the product description (Mastodon has room);
#               omit it for the tight Twitter budget.
# Out:     the message on stdout.
set -euo pipefail

MAX="${1:-280}"
WITH_DESC="${2:-}"
TAG="${TAG:?}"; URL="${URL:?}"; BODY="${BODY:-}"

# DESC (product description) and TAGS (hashtags) default to the Twitter copy but
# can be overridden per platform (Mastodon has its own approved description/tags).
DESC="${DESC:-Vault secrets engine for Keycloak: rotate service account passwords on-demand, random, audit-logged, never stored.}"
TAGS="${TAGS:-#Vault #Keycloak #IAM #OpenSource}"

# Strip a changelog bullet to readable text: drop the leading "* ", every trailing
# "([text](url))" link (PR + commit), and markdown bold markers.
clean() { sed -E 's/^[*-] +//; s/ *\(\[[^]]*\]\([^)]*\)\)//g; s/\*\*//g'; }
# Bullets under a "### <header>" section.
section() { awk -v h="### $1" '$0==h{f=1;next} /^### /{f=0} f && /^[*-] /'; }

feats="$(printf '%s\n' "$BODY" | section 'Features' | clean || true)"
fixes="$(printf '%s\n' "$BODY" | section 'Bug Fixes' | grep -ivE '^[*-] +bump .+ from .+ to ' | clean || true)"
candidates="$(printf '%s\n%s\n' "$feats" "$fixes" | sed '/^$/d')"

# Twitter-weighted length: count chars but treat the URL as 23.
weighted() { echo $(( $(printf '%s' "$1" | wc -m) - ${#URL} + 23 )); }

assemble() { # $1 = "what's new" block (may be empty)
  local wn="$1"
  printf '🔐 vault-plugin-secrets-keycloak %s\n' "$TAG"
  [ "$WITH_DESC" = "desc" ] && printf '\n%s\n' "$DESC"
  if [ -n "$wn" ]; then
    printf "\n✨ What's new:\n%s" "$wn"
  elif [ "$WITH_DESC" != "desc" ]; then
    printf '\n%s\n' "$DESC"
  fi
  printf '\n🔗 %s\n\n%s\n' "$URL" "$TAGS"
}

# Add bullets newest-interest-first while the whole message stays within budget.
wn=""
while IFS= read -r line; do
  [ -z "$line" ] && continue
  trial="${wn}• ${line}"$'\n'
  if [ "$(weighted "$(assemble "$trial")")" -le "$MAX" ]; then
    wn="$trial"
  else
    break
  fi
done <<EOF
$candidates
EOF

assemble "$wn"
