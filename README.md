# dns-blocker-daemon

install packages (really just *native-dns*):\
`npm i`

`node server.js` to start the server

to add a website to the blocked list (same shell as to where server is running - I like to use tmux):\
`block {website} {duration in milliseconds}`

to make the server run on boot, you'll need crontab
`crontab -e`

`@reboot /usr/bin/node /path/to/yourscript.js`\
^ **/opt/homebrew/bin/** for apple silicon (homebrew thing iirc)
