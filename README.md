# Carbon Black - Juniper Networks Sky ATP connector

The skyatp connector for Carbon Black submits infected hosts detected by a Cb Response server to the Sky ATP infected hosts blacklist.

Infected hosts are identified by watchlist alerts, you can configure any number of watchlists by name in a comma delimited list. 
The SKYATP connector will add hosts identified by alerts from these watchlists to the infected host feed in SKYATP. 
As alerts generated from these watchlists are resolved from within CbR, the CbR SkyAtp connector will remove the host from the blacklist/infected hosts feed - when there are no longer any outstanding issues needing resolution.

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:

```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-skyatp-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/skyatp/carbonblack-skyatp-connector.conf.template` file to `/etc/cb/integrations/skyatp/carbonblack-skyatp-connector.conf`. 

Edit this conf file and fill in the required variables:
```
`carbonblack_server_token` - Carbon Black API key 
`carbonblack_server_url` - Carbon Black server's base URL 
`skyatp_api_keys` - API keys
`watchlists` - List of Cb Response watchlists that you created in CbR UI
```

Once the software is configured, then you can start the connector via service cb-skyatp-connector start. Any errors will be logged into `/var/log/cb/integrations/skyatp/cb-skyatp-connector.log`. The connector will automatically create a feed in the connected Carbon Black server's console.

## Troubleshooting

If you suspect a problem, please first look at the Sky ATP connector logs found here: `/var/log/cb/integrations/skyatp/cb-skyatp-connector.log` (There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

Stop the service: `service cb-skyatp-connector stop`
Restart the service: `service cb-skyatp-connector start`


## Support

1. Use the [Developer Community Forum](https://community.carbonblack.com/t5/Developer-Relations/bd-p/developer-relations) to discuss issues and ideas with other API developers in the Carbon Black Community.
2. Report bugs and change requests through the GitHub issue tracker. Click on the + sign menu on the upper right of the screen and select New issue. You can also go to the Issues menu across the top of the page and click on New issue.
3. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
