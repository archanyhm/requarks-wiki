/* global WIKI */

// ------------------------------------
// Discord Account
// ------------------------------------

const DiscordStrategy = require('passport-discord').Strategy
const _ = require('lodash')

async function getGuildMember(accessToken, guildId) {
  const response = await fetch(
    `https://discord.com/api/v10/users/@me/guilds/${guildId}/member`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'User-Agent': 'Wiki.js'
      }
    }
  )
  
  if (!response.ok) {
    throw new Error(`Discord API error: ${response.status} ${response.statusText}`)
  }
  
  return response.json()
}

module.exports = {
  init(passport, conf) {
    passport.use(conf.key,
      new DiscordStrategy({
        clientID: conf.clientId,
        clientSecret: conf.clientSecret,
        authorizationURL: 'https://discord.com/api/oauth2/authorize?prompt=none',
        callbackURL: conf.callbackURL,
        scope: 'identify email guilds guilds.members.read',
        passReqToCallback: true
      }, async (req, accessToken, refreshToken, profile, cb) => {
        try {
          if (conf.roles) {
            const authRoles = conf.roles.split()
            const memberData = await getGuildMember(accessToken, conf.guildId)
            const memberRoles = memberData.roles || []
            if (!authRoles.some(role => memberRoles.includes(role))) {
              throw new WIKI.Error.AuthLoginFailed()
            }
          } else if (conf.guildId && !_.some(profile.guilds, { id: conf.guildId })) {
            throw new WIKI.Error.AuthLoginFailed()
          }

          const user = await WIKI.models.users.processProfile({
            providerKey: req.params.strategy,
            profile: {
              ...profile,
              displayName: profile.username,
              picture: `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
            }
          })

          if (conf.mapRoles && conf.guildId) {
            try {
              const memberData = await getGuildMember(accessToken, conf.guildId)
              const discordRoles = memberData.roles || []
              const roleMappings = JSON.parse(conf.roleMappings || '{}')
              const currentGroups = (await user.$relatedQuery('groups').select('groups.id')).map(g => g.id)
              
              // Build expected groups from role mappings
              const expectedGroups = []
              for (const [discordRoleId, groupName] of Object.entries(roleMappings)) {
                if (discordRoles.includes(discordRoleId)) {
                  const group = Object.values(WIKI.auth.groups).find(g => g.name === groupName)
                  if (group) {
                    expectedGroups.push(group.id)
                  }
                }
              }
              
              // Sync groups
              for (const groupId of _.difference(expectedGroups, currentGroups)) {
                await user.$relatedQuery('groups').relate(groupId)
              }
              for (const groupId of _.difference(currentGroups, expectedGroups)) {
                await user.$relatedQuery('groups').unrelate().where('groupId', groupId)
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
