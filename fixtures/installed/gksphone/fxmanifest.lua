fx_version 'cerulean'
game 'gta5'

author 'GKSHOP (synthetic fixture)'
description 'Synthetic test resource. Not a real GKSHOP product.'
version '1.0.0'

escrow_ignore {
  'config.lua',
  'client/custom.lua',
}

client_scripts {
  'config.lua',
  'client/main.lua',
  'client/custom.lua',
}

server_scripts {
  'config.lua',
  'server/main.lua',
}
