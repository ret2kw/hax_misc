hax_misc
========

Collection of random scripts written hastily while on various gigs




###search_da###
This script uses the python [MSFRPC] (https://github.com/SpiderLabs/msfrpc) library to automate metasploit. Script runs auxiliary/scanner/smb/smb_enumusers_domain against an IP range searching for specific users (think DA).


###screenshotter###
Simple script that you supply a line delimited ip address list, a port number and whether you want to scan https urls also, i.e. negotiate SSL. It then uses [PhantomJS] (http://phantomjs.org/) and [Selenium] (http://www.seleniumhq.org/) to render and screenshot the webpages. Similar to [Peeping Tom] (https://bitbucket.org/LaNMaSteR53/peepingtom/) but stripped down. 
