# Meraki Dashboard API Script Starter
A template designed to help others learn Python and or the Meraki Dashboard API. 

# Summary
I used the Meraki Dashboard API to learn Python and would like to now provide an easy way for others to follow in my footsteps. I have created this simple script starter that will allow the user to focus on learning Python more than the API . I do this by constructing a `sites` variable. In the context of this script, a "site" is defined as a Meraki Network. I use Pickle (Python object serialization) to store data across all the sites in a given organization so that you do not have to keep making API calls while building your scripts. Once your script is built, you can make fresh API calls to ensure everything works with live data. While this variable does not contain every single bit of data you can get from the Dashboard API, it does contain enough information to get you started on a very large variety of scripts.

I have another repository in which I use this sites variable to perform in-depth traffic analysis. Check it out [here](https://github.com/picnicsecurity/Meraki-Traffic-Analyzer)

The other Meraki repository that I have, [Meraki API Toolbox](https://github.com/picnicsecurity/MerakiAPIToolBox), was made using the v0 of the Dashboard API. If I had time I would rewrite it using this sites variable as it would greatly optomize the code and allow me to add a bunch of features that were not possible with the v0 of the Dashboard API. 

## Usage
 - API Key Setup
     - On [Line 398](https://github.com/picnicsecurity/Meraki-Dashboard-API-Script-Starter/blob/main/starter.py#L398) you will a variable called `apikey`. This is where you put your [Dashboard API Key](https://documentation.meraki.com/General_Administration/Other_Topics/The_Cisco_Meraki_Dashboard_API). By default the script will assume that your key is in a file in the same directory called `apikey`. The .gitignore will automatically ignore this file in an effort to prevent unintentional key leakage.
 - Python Console
     - I personally do not suggest you do it this way as it will be the least friendly. However, if it is your only option, here is how you would get it loaded up
        ```
        >>> import starter.py
        >>> # This script will now be loaded into the console for you to use
        >>> # If you are using tmux and making modifications to it, after you hit save you can reload it by doing the following
        >>> reload('sites.py')
        ```
 - PyCharm
     - This is what I use to do all of my Python scripting and debugging. There are all sorts of useful features in this IDE that make it my absolute favorite
     - See these links for getting this project setup in Github 
         - https://www.jetbrains.com/help/pycharm/github.html
         - https://www.jetbrains.com/help/pycharm/manage-projects-hosted-on-github.html#clone-from-GitHub
     - After you have PyCharm setup and the dependencies installed, all you need to do is right click anywhere in the script and select "Run File in Python Console"
     - Note that when you run things in the Python Console on PyCharm that things may not always print out correctly (for example the progress bars)    
## Examples
 - Printing the name of your organization
    ```
    for site in sites:
         if site['Name'] == 'Organization':
             print(site['Organization Name'])
     
    Picnic Security
    ```
 - Printing the names of your sites
    ```
    for site in sites:
        if 'Organization' not in site['Name']:
            print(site['Name'])
    
    ABC
    DEF
    AWS
    ```
 - Defining an IP and determining which site(s) that IP can be found in 
    ```
    # Documentation for the netaddr library can be found here https://netaddr.readthedocs.io/en/latest/
    ip = IPAddress('10.0.0.100')        
    for site in sites:
        # If there is any IPNetwork() in the site's list of Cidrs in which our defined IP would be a part of it
        if any(network for network in site['Cidrs'] if ip in network):
            # Then print that site's name
            print(site['Name'])
    
    DEF
    ```
 - Defining a specific site to work with using list comprehension
    ```
    DEF = [site for site in sites if site['Name'] == 'DEF'][0]
    ```
 - Using the network clients data to determine where in a site an IP has been seen
    ```
    ip_we_are_looking_for = IPAddress('10.0.0.100')
    for client in DEF['Clients']:
        if client['ip'] is not None:
            client_ip = IPAddress(client['ip'])
        else:
            continue
        if client_ip == ip_we_are_looking_for:
            print("Found the IP %s in %s's network clients data" % (client['ip'], DEF['Name']))
            print("This device was last seen on switch %s port %s" % (client['recentDeviceName'], client['switchport']))
    
    Found the IP 10.0.0.100 in DEF's network clients data
    This device was last seen on switch DEF-4-SW03 port 20
    ```
 - Doing the same thing above except this time we look at the each device's client data
     - Note that the difference between these two is that when looking at the device's client data you will generally only see clients that are online but the network's client data includes clients that are not online
    ```        
    for device in DEF['Devices']:
        for client in device['clients']:
            if client['ip'] is not None:
                client_ip = IPAddress(client['ip'])
            else:
                continue
            if client_ip == ip_we_are_looking_for:
                print("Found the IP %s in %s's device client data" % (ip_we_are_looking_for, DEF['Name']))
                print("This client is on switch %s port %s" % (device['name'], client['switchport']))
    
    Found the IP 10.0.0.100 in DEF's device client data
    This client is on switch DEF-4-SW03 port 20
    ```
 - Doing the same thing above except using API calls rather than the `sites` variable
     - Note that we would generally put the results of an API call into a variable before iterating over it. This example is just meant to pull back the curtain a little bit and show you what my `sites` variable did ahead of time for you           
    ```
    dashboard = mer.DashboardAPI(
        api_key=apikey,
        print_console=False,
        maximum_retries=3,
        wait_on_rate_limit=True,
        log_path=MERLOGDIR
    )
    ip_we_are_looking_for = IPAddress('10.0.0.100')
    for organization in dashboard.organizations.getOrganizations():
        for network in dashboard.organizations.getOrganizationNetworks(organization['id']):
            for device in dashboard.networks.getNetworkDevices(network['id']):
                for client in dashboard.networks.getNetworkDevices(device['serial']):
                    if client['ip'] is not None and IPAddress(client['ip']) == ip_we_are_looking_for:
                        print("Found the IP %s in %s's device client data" % (ip_we_are_looking_for, network['name']))
                        print("This client is on switch %s port %s" % (device['name'], client['switchport']))
    
    Found the IP 10.0.0.100 in DEF's device client data
    This client is on switch DEF-4-SW03 port 20
    ```

## Sites Variable Structure
```
Sites = [
    # For each site in the orginization we will have the following dictionary 
    {
        'ACL': [
            # Note that I have customized the data returned from the API call for ACL/FW/VPN rules
            # This is because the ACL vs FW/VPN data is slightly different so in an effort to keep things easy I made it uniform
            {
                '#': str,
                'comment': str,
                'dstCidr': [
                    IPNetwork()
                ],
                'policy': str,
                'srcCidr': [
                    IPNetwork()
                ]
            }
        ], 
        # This is a consolidated down list of all the subnets that are in the network
        'Cidrs': [
            IPNetwork()
        ], 
        # This is where all the data collected from the dashboard.networks.getNetworkClients() will go
        # However I am consistently getting 502 Bad Gateway errors so I cant fully populate this variable
        # It will only have the first 10 clients from the first page
        # A much more complete list of clients can be found in the Devices variable
        # The reason these are separate is because this API call also shows you clients that are offline
        'Clients': [
            {
                'description' = str,
                'firstSeen' = str,
                'groupPolicy8021x' = str,
                'id' = str,
                'ip' = str,
                'ip6' = str,
                'ip6Local' = str,
                'lastSeen' = str,
                'mac' = str,
                'manufacturer' = str,
                'notes' = str,
                'os' = str,
                'recentDeviceMac' = str,
                'recentDeviceName' = str,
                'recentDeviceSerial' = str,
                'smInstalled' = bool,
                'ssid' = str,
                'status' = str,
                'switchport' = str,
                'usage' = {
                    'sent': int, 
                    'recv': int
                },
                'user' = str,
                'vlan' = int
            }
        ],
        'Devices': [
            {
                'address' = str, 
                'clients' = {
                    'description' = str,
                    'dhcpHostname' = str,
                    'id' = str,
                    'ip' = str,
                    'mac' = str,
                    'mdnsName' = str,
                    'switchport' = str,
                    'usage' = {
                        'sent': int, 
                        'recv': int
                    },
                    'user' = str,
                    'vlan' = int
                }
                'firmware' = str,
                'floorPlanId' = str,
                'lanIp' = str,
                'lat' = float,
                'lng' = float,
                'mac' = str,
                'model' = str, 
                'name' = str,
                'networkId' = str,
                'serial' = str,
                'tags' = [
                    str
                ],
                'url': str                            
            }
        ], 
        # These are the traffic flow rules you will find on your MX security appliance 
        'Firewall': [
            {
                
                '#': str,
                'comment': str,
                'dstCidr': [
                    IPNetwork()
                ],
                'policy': str,
                'srcCidr': [
                    IPNetwork()
                ],
            }
        ],
        'Name': str, 
        'NetworkID': str,
        # If the site is part of a site-to-site VPN setup, then its peers will be listed here
        'Peers': [
            # This is a tuple containing the network ID and name of the peer
            (str, str)    
        ], 
        'VLANS': [
            {
                'interfaceId' = str,
                'interfaceIp' = str,
                # If the VLAN is being shared across the site-to-site VPN
                'inVpn' = bool,
                # The Layer 3 switch or switch stack that has the interface IP for the VLAN
                'location' = str,
                # Since a VLAN interface can be on MX and MS this tells us which
                'MS' = bool,
                'multicastRouting' = str,
                'name' = str,
                'ospfSettings' = {
                    'area': str
                },
                'subnet' = IPNetwork(),
                'vlanId' = int  
            }
        ], 
        # A list of all the subnets from this network that are being shared out on the site-to-site VPN
        'VPNSubnets': [
            IPNetwork()    
        ]
    },
    # There will also be a special Organization Wide entry for things like site-to-site VPN rules
    {
        'Name': 'Organization',
        'Organization Name': organization['name'],
        # The site-to-site VPN rules
        'VPN Rules': [
            {
                '#': str,
                'comment': str,
                'dstCidr': [
                    IPNetwork()
                ],
                'policy': str,
                'srcCidr': [
                    IPNetwork()
                ]
            }
        ],
        'NetworkID': organization['id'],
        'Devices': [],
        'Clients': [],
        'VLANS': [],
        'Peers': [],
        'VPNSubnets': [],
        'ACL': [],
        'Firewall': [],
        'Cidrs': []
    }
]
```
