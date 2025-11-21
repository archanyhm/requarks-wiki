/* global WIKI */

// ------------------------------------
// Discord Account
// ------------------------------------

const DiscordStrategy = require('passport-discord').Strategy
const _ = require('lodash')

/**
 * Fetch Discord Guild Member with Retry Logic
 */
async function getGuildMember(accessToken, guildId, retries = 3) {
  const url = `https://discord.com/api/v10/users/@me/guilds/${guildId}/member`
  
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'User-Agent': 'Wiki.js'
        }
      })

      if (response.ok) {
        return await response.json()
      }

      // Don't retry on client errors (4xx), except 429 (Rate Limit)
      if (response.status >= 400 && response.status < 500 && response.status !== 429) {
        WIKI.logger.warn(`Discord API Error: ${response.status} ${response.statusText}`)
        throw new Error(`Discord API error: ${response.status}`)
      }
      
      // If 429 or 5xx, wait and retry
      const delay = 1000 * Math.pow(2, i) // Exponential backoff: 1s, 2s, 4s
      await new Promise(resolve => setTimeout(resolve, delay))
    } catch (err) {
      if (i === retries - 1) throw err
    }
  }
}

/**
 * Get correct avatar URL handling default avatars
 */
function getAvatarUrl(profile) {
  if (profile.avatar) {
    return `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
  }
  
  // Handle default avatars
  // Logic based on Discord API docs
  let index = 0
  if (profile.discriminator && profile.discriminator !== '0') {
    index = parseInt(profile.discriminator) % 5
  } else {
    index = (BigInt(profile.id) >> 22n) % 6n
  }
  return `https://cdn.discordapp.com/embed/avatars/${index}.png`
}

module.exports = {
  init(passport, conf) {
    // Dynamic Scopes: Only request privileged scopes if we actually need to check guilds/roles
    const scopes = ['identify', 'email']
    if (conf.guildId) {
      scopes.push('guilds', 'guilds.members.read')
    }

    passport.use(conf.key,
      new DiscordStrategy({
        clientID: conf.clientId,
        clientSecret: conf.clientSecret,
        authorizationURL: 'https://discord.com/api/oauth2/authorize?prompt=none',
        callbackURL: conf.callbackURL,
        scope: scopes,
        passReqToCallback: true
      }, async (req, accessToken, refreshToken, profile, cb) => {
        try {
          let memberData = null

          // 1. Fetch Member Data (if configured)
          if ((conf.roles || conf.mapRoles) && conf.guildId) {
            try {
              memberData = await getGuildMember(accessToken, conf.guildId)
            } catch (err) {
              WIKI.logger.warn('Failed to fetch Discord member data:', err.message)
              // If roles are strictly required, fail the login
              if (conf.roles) {
                throw new WIKI.Error.AuthLoginFailed()
              }
            }
          }

          // 2. Validation Checks
          if (conf.roles) {
            if (!memberData) {
              throw new WIKI.Error.AuthLoginFailed()
            }
            const authRoles = conf.roles.split(',').map(r => r.trim())
            const memberRoles = memberData.roles || []
            if (!authRoles.some(role => memberRoles.includes(role))) {
              throw new WIKI.Error.AuthLoginFailed()
            }
          } else if (conf.guildId && !_.some(profile.guilds, { id: conf.guildId })) {
            // If only Guild ID is required (no specific roles)
            throw new WIKI.Error.AuthLoginFailed()
          }

          // 3. Create/Update User
          const user = await WIKI.models.users.processProfile({
            providerKey: req.params.strategy,
            profile: {
              ...profile,
              displayName: profile.global_name || profile.username, // Prefer global display name
              picture: getAvatarUrl(profile)
            }
          })

          // 4. Role Mapping (Safe Sync)
          if (conf.mapRoles && conf.guildId && memberData) {
            try {
              const discordRoles = memberData.roles || []
              let roleMappings = {}
              try {
                roleMappings = JSON.parse(conf.roleMappings || '{}')
              } catch (e) {
                WIKI.logger.warn('Discord Auth: Invalid JSON in Role Mappings')
              }

              // Calculate which Wiki.js Group IDs are managed by this configuration
              const allManagedGroupNames = Object.values(roleMappings)
              const allManagedGroups = _.filter(WIKI.auth.groups, g => allManagedGroupNames.includes(g.name))
              const allManagedGroupIds = allManagedGroups.map(g => g.id)

              // Calculate groups the user SHOULD have based on their Discord roles
              const expectedGroups = []
              for (const [discordRoleId, groupName] of Object.entries(roleMappings)) {
                if (discordRoles.includes(discordRoleId)) {
                  const group = Object.values(WIKI.auth.groups).find(g => g.name === groupName)
                  if (group) {
                    expectedGroups.push(group.id)
                  }
                }
              }

              const currentGroups = (await user.$relatedQuery('groups').select('groups.id')).map(g => g.id)

              // Add missing groups
              const groupsToAdd = _.difference(expectedGroups, currentGroups)
              if (groupsToAdd.length > 0) {
                await Promise.all(groupsToAdd.map(groupId => user.$relatedQuery('groups').relate(groupId)))
              }

              // Remove groups that are:
              // 1. Currently assigned to the user
              // 2. NOT in the expected list
              // 3. BUT ARE part of the managed set (prevent removing manually assigned groups)
              const groupsToRemove = currentGroups.filter(gid => 
                !expectedGroups.includes(gid) && 
                allManagedGroupIds.includes(gid)
              )

              if (groupsToRemove.length > 0) {
                await Promise.all(groupsToRemove.map(groupId =>
                  user.$relatedQuery('groups').unrelate().where('groupId', groupId)
                ))
              }
            } catch (err) {
              WIKI.logger.warn(`Failed to map Discord roles for user ${user.id}:`, err.message)
            }
          }

          cb(null, user)
        } catch (err) {
          cb(err, null)
        }
      }
      ))
  }
}
