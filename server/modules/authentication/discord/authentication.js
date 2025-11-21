/* global WIKI */

// ------------------------------------
// Discord Account
// ------------------------------------

const DiscordStrategy = require('passport-discord').Strategy
const DiscordOauth2 = require('./node_modules/discord-oauth2/index.js')
const _ = require('lodash')


module.exports = {
  init(passport, conf) {
    const discord = new DiscordOauth2()
    passport.use(conf.key,
      new DiscordStrategy({
        clientID: conf.clientId,
        clientSecret: conf.clientSecret,
        authorizationURL: 'https://discord.com/api/oauth2/authorize?prompt=none',
        callbackURL: conf.callbackURL,
        scope: 'identify email guilds',
        passReqToCallback: true
      }, async (req, accessToken, refreshToken, profile, cb) => {
        try {
          if (conf.roles) {
            const authRoles = conf.roles.split();
            const { roles } = await discord.getGuildMember(accessToken, conf.guildId);
            if (authRoles.every(role => roles.includes(role)))
              throw new WIKI.Error.AuthLoginFailed()
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
            const memberData = await discord.getGuildMember(accessToken, conf.guildId)
            const discordRoles = memberData.roles || []
            
            try {
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
