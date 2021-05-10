import meraki as mer
import pickle
from netaddr import *
import netaddr
from tqdm import tqdm
from tqdm.utils import _term_move_up
import os
import time
import shutil


# Logs go into a log directory and are $(unix time).log
LOGDIR = os.path.join(os.getcwd(), "logs")
LOGFILEPATH = os.path.join(LOGDIR, str(int(time.time())) + ".log")
# Meraki api calls generate a lot of cruff so we will jam them into here
MERLOGDIR = os.path.join(os.getcwd(), "meraki_logs")
if not os.path.isdir(LOGDIR):
    os.mkdir(LOGDIR)
    LOGFILE = open(LOGFILEPATH, "w")
else:
    LOGFILE = open(LOGFILEPATH, "w")
if not os.path.isdir(MERLOGDIR):
    os.mkdir(MERLOGDIR)

global VERBOSE
VERBOSE = False

global TERMSIZE
TERMSIZE = 1
try:
    TERMSIZE = TERMSIZE
except OSError as e:
    # Couldnt get the size of the terminal so leaving it at the default of 15
    TERMSIZE = 15

# Controls verbose output
# Thanks to this stack overflow post I am able to upgrade this function to handle tqdm progress bars
# https://stackoverflow.com/questions/53874150/python-tqdm-is-there-a-way-to-print-something-between-a-progress-bar-and-what
def printv(m, pbar=None):
    if type(m) is list:
        m = "[" + ', '.join(str(x) for x in m) + "]"
    if VERBOSE:
        if pbar is not None:
            border = "=" * (TERMSIZE)
            clear_border = _term_move_up() + "\r" + " " * len(border) + "\r"
            pbar.write(clear_border + "VERBOSE: %s" % m)
            pbar.write(border)
        else:
            print("VERBOSE: " + m)
        LOGFILE.write("VERBOSE: " + m + "\n")
    else:
        LOGFILE.write("VERBOSE: " + m + "\n")


# This saves an incredible amount of time as gathering client data can take 5-10 minutes on a larger scale
def load_sites(filename):
    sites = pickle.load(open(filename, "rb"))
    return sites


# client data is the only actual data that can go stale, saving our site variable to a file saves time in future runs
def save_sites(filename, sites):
    pickle.dump(sites, open(filename, "wb"))


def get_vpn_rules(dashboard, organizationId, pbar=None):
    orgRules = []
    printv("Gathering Site-to-Site firewall rules for the organization", pbar)
    try:
        for x, acl in enumerate(
                dashboard.appliance.getOrganizationApplianceVpnVpnFirewallRules(organizationId)['rules'][:-1]):
            # Cleaning up the dict and formatting it accordingly
            tmp = {'#': "VPN-" + str(x + 1).zfill(2), 'comment': acl['comment'], 'policy': acl['policy']}
            # Formatting values
            if 'any' in acl['srcCidr'].lower():
                tmp['srcCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['srcCidr'] = [IPNetwork(network) for network in acl['srcCidr'].split(",")]
            if 'any' in acl['destCidr'].lower():
                tmp['dstCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['dstCidr'] = [IPNetwork(network) for network in acl['destCidr'].split(",")]
            orgRules.append(tmp)
    except mer.exceptions.APIError as e:
        orgRules = None
    return orgRules


def get_org_remote_vpn_participants(dashboard, organizationId, networkId):
    # This shows us what each site is connected to on the S2S VPN
    orgVpnData = dashboard.appliance.getOrganizationApplianceVpnStats(organizationId=organizationId)
    siteVpnData = None
    siteVpnData = [network for network in orgVpnData if network['networkId'] == networkId]
    if siteVpnData is not None:
        siteVpnData = siteVpnData[0]
    peers = [(peer['networkId'], peer['networkName']) for peer in siteVpnData['merakiVpnPeers']]
    peers.append((siteVpnData['networkId'], siteVpnData['networkName']))
    return peers


def get_acls(dashboard, networkId, pbar=None):
    # MS ACLs
    msACL = []
    printv("Gathering ACL rules on the MS switches", pbar)
    try:
        for x, acl in enumerate(dashboard.switch.getNetworkSwitchAccessControlLists(networkId)['rules']):
            # Cleaning up the dict and formatting it accordingly
            tmp = {}
            tmp['#'] = "MS-" + str(x + 1).zfill(2)
            tmp['comment'] = acl['comment']
            tmp['policy'] = acl['policy']
            # Formatting values
            if 'any' in acl['srcCidr'].lower():
                tmp['srcCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['srcCidr'] = [IPNetwork(network) for network in acl['srcCidr'].split(",")]
            if 'any' in acl['dstCidr'].lower():
                tmp['dstCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['dstCidr'] = [IPNetwork(network) for network in acl['dstCidr'].split(",")]
            msACL.append(tmp)
    except mer.exceptions.APIError as e:
        msACL = []
    # MX Firewall
    mxFW = []
    printv("Gathering Firewalls rules on the MX appliances", pbar)
    try:
        for x, acl in enumerate(
                dashboard.appliance.getNetworkApplianceFirewallL3FirewallRules(networkId)['rules'][:-1]):
            # Cleaning up the dict and formatting it accordingly
            tmp = {}
            tmp['#'] = "MX-" + str(x + 1).zfill(2)
            tmp['comment'] = acl['comment']
            tmp['policy'] = acl['policy']
            # Formatting values
            if 'any' in acl['srcCidr'].lower():
                tmp['srcCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['srcCidr'] = [IPNetwork(network) for network in acl['srcCidr'].split(",")]
            if 'any' in acl['destCidr'].lower():
                tmp['dstCidr'] = [IPNetwork('0.0.0.0/0')]
            else:
                tmp['dstCidr'] = [IPNetwork(network) for network in acl['destCidr'].split(",")]
            mxFW.append(tmp)
    except mer.exceptions.APIError as e:
        mxFW = []
    return msACL, mxFW


def get_device_clients(dashboard, device, clientsPBar, n=1.0):
    clientsPBar.set_description("Gathering client data on %s" % device['name'])
    clientData = [c for c in dashboard.devices.getDeviceClients(device['serial'])]
    clientsPBar.update(n)
    clientsPBar.set_description("Gathering LLDP/CDP data on %s" % device['name'])
    portData = dashboard.devices.getDeviceLldpCdp(device['serial'])
    if 'ports' in portData:
        for port, data in portData['ports'].items():
            client = {
                'description': None,
                'dhcpHostname': None,
                'id': None,
                'ip': None,
                'mac': None,
                'mdnsName': None,
                'switchport': port,
                'usage': {'sent': 0.0, 'recv': 0.0},
                'user': None,
                'vlan': None
            }
            # Checking for any LLDP data
            if 'lldp' in portData['ports']:
                if 'managementAddress' in portData['ports'][port]['lldp']:
                    client['ip'] = portData['ports'][port]['lldp']['managementAddress']
                if 'systemName' in portData['ports'][port]['lldp']:
                    client['description'] = portData['ports'][port]['lldp']['systemName']
                if 'portId' in portData['ports'][port]['lldp']:
                    if ":" in portData['ports'][port]['lldp']['portId']:
                        macAddr = portData['ports'][port]['lldp']['portId']
                        macAddr = str(':'.join(macAddr[i:i + 2] for i in range(0, 12, 2))).upper()
                        client['mac'] = macAddr
            # Checking for any CDP data
            if 'cdp' in portData['ports'][port]:
                if client['mac'] is None and 'deviceId' in portData['ports'][port]['cdp']:
                    macAddr = portData['ports'][port]['cdp']['deviceId']
                    macAddr = str(':'.join(macAddr[i:i + 2] for i in range(0, 12, 2))).upper()
                    client['mac'] = macAddr
                else:
                    if 'deviceId' in portData['ports'][port]['cdp'] and client['description'] is None:
                        macAddr = portData['ports'][port]['cdp']['deviceId']
                        macAddr = str(':'.join(macAddr[i:i + 2] for i in range(0, 12, 2))).upper()
                        client['description'] = macAddr
                if client['ip'] is None and 'address' in portData['ports'][port]['cdp']:
                    client['ip'] = portData['ports'][port]['cdp']['address']
            if client['ip'] is not None:
                clientData.append(client)
    device['clients'] = clientData
    clientsPBar.update(n)
    return device

def get_sites(dashboard, organizationId, networks, get_clients=False):
    sites = []

    # First thing we do is gather some globals
    organization = dashboard.organizations.getOrganization(organizationId)
    s2sRules = get_vpn_rules(dashboard, organizationId, None)
    organizationWide = {
        'Name': 'Organization',
        'Organization Name': organization['name'],
        'VPN Rules': s2sRules,
        'NetworkID': organization['id'],
        'Devices': [],
        'Clients': [],
        'VLANS': [],
        'Peers': [],
        'VPNSubnets': [],
        'ACL': [],
        'Firewall': [],
        'Cidrs': [],
        'Products': []
    }
    sites.append(organizationWide)
    print(("-" * (TERMSIZE)) + "\n")

    for network in networks:
        sitesPBar = tqdm(range(0, 100), leave=True)
        sitesPBar.set_description("Processing %s" % network['name'])

        # Site Name and ID
        printv("Gathering identifiers", sitesPBar)
        siteName = network['name']
        networkId = network['id']
        products = network['productTypes']

        # VPN Subnets
        printv("Gathering VPN data", sitesPBar)
        peers = []
        vpnSubnets = []
        if 'appliance' in products:
            peers = get_org_remote_vpn_participants(dashboard, organizationId, networkId)
            sitesPBar.update(10)
            vpnSubnets = [
                IPNetwork(subnet['localSubnet'])
                for subnet in dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(networkId)['subnets']
                if subnet['useVpn']
            ]
            sitesPBar.update(10)
        else:
            sitesPBar.update(20) # 20%

        # VLANs
        printv("Gathering VLAN data from switch stacks", sitesPBar)
        vlanList = []
        checkedSerials = []
        cidrList = []
        # Grabbing VLANs from any MS series switches starting with switch stacks
        if 'switch' in products:
            try:
                for stack in dashboard.switch.getNetworkSwitchStacks(networkId):
                    for serial in stack['serials']:
                        checkedSerials.append(serial)
                    for vlan in dashboard.switch.getNetworkSwitchStackRoutingInterfaces(networkId=networkId,
                                                                                        switchStackId=stack['id']):
                        vlan['subnet'] = IPNetwork(vlan['subnet'])
                        if vlan['subnet'] in vpnSubnets:
                            vlan['inVpn'] = True
                        else:
                            vlan['inVpn'] = False
                        vlan['MS'] = True
                        vlan['location'] = stack['name']
                        cidrList.append(vlan['subnet'])
                        vlanList.append(vlan)
            except mer.exceptions.APIError as e:
                # This error will be thrown when dealing with networks that do not have switch stacks
                printv("No switch stacks in this network", sitesPBar)
        sitesPBar.update(10) # 30%

        # Next we check for any layer 3 interfaces on switches that are not in stacks
        # Gathering the devices
        printv("Gathering port data from switches", sitesPBar)
        devs = []
        if 'switch' in products or 'wireless' in products:
            for device in dashboard.networks.getNetworkDevices(networkId=networkId):
                if 'name' not in device:
                    device['name'] = device['mac']
                if 'MS' in device['model']:
                    ports = dashboard.switch.getDeviceSwitchPorts(serial=device['serial'])
                    if ports:
                        port_keys = list(set().union(*(p.keys() for p in ports)))
                        port_statuses = dashboard.switch.getDeviceSwitchPortsStatuses(device['serial'])
                        if port_statuses:
                            port_status_keys = list(set().union(*(p.keys() for p in port_statuses)))
                            port_status_keys.remove("portId")
                            port_status_keys.remove("enabled")
                        for port in ports:
                            if port_statuses:
                                status = [p for p in port_statuses if p['portId'] == port['portId']]
                                if status:
                                    status = status[0]
                                    for k in port_status_keys:
                                        if k in status:
                                            port[k] = status[k]
                                            if k == 'usageInKb':
                                                useageInMb = {
                                                    "total": status['usageInKb']['total'] / 1000,
                                                    "sent": status['usageInKb']['sent'] / 1000,
                                                    "recv": status['usageInKb']['recv'] / 1000
                                                }
                                                port['usageInMb'] = useageInMb
                                            if k == 'trafficInKbps':
                                                trafficInMbps = {
                                                    "total": status['trafficInKbps']['total'] / 1000,
                                                    "sent": status['trafficInKbps']['sent'] / 1000,
                                                    "recv": status['trafficInKbps']['recv'] / 1000
                                                }
                                                port['trafficInMbps'] = trafficInMbps
                                        else:
                                            port[k] = None
                                else:
                                    for k in port_status_keys:
                                        port[k] = None
                            for k in port_keys:
                                if k not in port:
                                    port[k] = None
                        device['ports'] = ports
                    else:
                        device['ports'] = None
                    devs.append(device)
                if 'MR' in device['model']:
                    device['ports'] = None
                    devs.append(device)
            # Now we sort all of the data
            #msDevices.sort(key=lambda x: x['name'], reverse=True)
            #mrDevices.sort(key=lambda x: x['name'], reverse=True)
            # Since the juicy information that we are most likely to care about will be in the MS, we put it first
            devices = sorted(devs, key=lambda x: (x['model'], x['name']), reverse=True)
        else:
            devices = []
        sitesPBar.update(20) # 50%

        # Checking for layer 3 interfaces
        if 'switch' in products:
            for device in devices:
                if device['serial'] in checkedSerials or 'MS' not in device['model']:
                    continue
                else:
                    for vlan in dashboard.switch.getDeviceSwitchRoutingInterfaces(device['serial']):
                        vlan['subnet'] = IPNetwork(vlan['subnet'])
                        if vlan['subnet'] in vpnSubnets:
                            vlan['inVpn'] = True
                        else:
                            vlan['inVpn'] = False
                        vlan['MS'] = True
                        vlan['location'] = device['name']
                        cidrList.append(vlan['subnet'])
                        vlanList.append(vlan)
        sitesPBar.update(10) # 60%

        # Lastly we get any VLANs that might be on the MX
        printv("Gathering VLAN data from MX security appliances", sitesPBar)
        if 'appliance' in products:
            try:
                for vlan in dashboard.appliance.getNetworkApplianceVlans(networkId):
                    vlan['vlanId'] = vlan['id']
                    vlan['subnet'] = IPNetwork(vlan['subnet'])
                    if vlan['subnet'] in vpnSubnets:
                        vlan['inVpn'] = True
                    else:
                        vlan['inVpn'] = False
                    vlan['MS'] = False
                    vlan['location'] = 'Appliance'
                    cidrList.append(vlan['subnet'])
                    vlanList.append(vlan)
            except mer.exceptions.APIError:
                printv("No VLANs exist on security appliances", sitesPBar)
        sitesPBar.update(10) # 70%

        # This can shave off a couple of iterations by allowing us to determine if an ip is even going to be in a site
        # Rather than going over 80 VLANs we instead go over 10 cidrs. Having to do 10 extra iterations is worth it
        # if we can save ourself from having to do 70 more
        # You will see this come into play in the get_ip_data function
        printv("Consolidating site's subnets into CIDR list", sitesPBar)
        cidrs = cidr_merge(cidrList)

        clients = []
        if not get_clients:
            printv("Gathering client data from the site's devices", sitesPBar)
            if os.path.isfile('sites.pkl.old'):
                printv("Loading previous clients data", sitesPBar)
                sites_bkp = load_sites('sites.pkl.old')
                site_bkp = [site for site in sites_bkp if site['Name'] == siteName]
                if site_bkp:
                    printv("Found site in previous data", sitesPBar)
                    clients = site_bkp[0]['Clients']
                    printv("Restoring device client data", sitesPBar)
                    for device in site_bkp[0]['Devices']:
                        # Getting current matching device
                        dev = [d for d in devices if d['mac'] == device['mac']]
                        if dev:
                            dev[0]['clients'] = device['clients']
                else:
                    printv("No client data for this site found", sitesPBar)
                    # Since the user does not want us to be making any client calls we just leave it as an empty list
                    for device in devices:
                        if 'clients' not in device:
                            device['clients'] = []
            else:
                printv("No sites pickle found", sitesPBar)
                for device in devices:
                    if 'clients' not in device:
                        device['clients'] = []
        else:
            # Gathering all the client data from the switches
            printv("Gathering client data from the site's devices", sitesPBar)
            if len(devices) > 0:
                n = float(str("{:.2f}".format((10 / (len(devices) * 2)))))
            for device in devices:
                clientData = dashboard.devices.getDeviceClients(device['serial'])
                if clientData:
                    # Ensuring all the dicts have all the same keys
                    client_keys = list(set().union(*(c.keys() for c in clientData)))
                    for client in clientData:
                        for k in client_keys:
                            if k not in client:
                                client[k] = None
                else:
                    device['clients'] = []
                sitesPBar.update(n)
            # I have been getting random 502 Bad Gateway errors with this api call which is unfortunate
            # This would be the much more ideal way of getting the clients on the network
            # The 'clients' property I added on to each device is messy at best but until this works its our only option
            printv("Gathering a sample of the network client data", sitesPBar)
            clients = dashboard.networks.getNetworkClients(networkId)
        # In case our floats didnt get us perfectly to the 85% we are supposed to be at
        sitesPBar.n = 85
        sitesPBar.refresh()

        # Getting ACL and Firewall Rules
        printv("Gathering MS ACL and MX Firewall data", sitesPBar)
        msACL, mxFW = get_acls(dashboard, networkId, products, sitesPBar)
        # Progress now at 95%

        printv("Creating site dictionary", sitesPBar)
        site = {
            'Name': siteName,
            'NetworkID': networkId,
            'Devices': devices,
            'Clients': clients,
            'VLANS': vlanList,
            'Peers': peers,
            'VPNSubnets': vpnSubnets,
            'ACL': msACL,
            'Firewall': mxFW,
            'Cidrs': cidrs,
            'Products': products
        }
        sites.append(site)
        sitesPBar.update(10) # 100%
        sitesPBar.close()	
        print(("-" * (TERMSIZE)) + "\n")
    return sites


apikey = ''
if apikey == '':
    with open('apikey', 'r') as k:
        apikey = k.readline().strip()
dashboard = mer.DashboardAPI(
    api_key=apikey,
    print_console=VERBOSE,
    maximum_retries=3,
    wait_on_rate_limit=True,
    log_path=MERLOGDIR,
    retry_4xx_error=True,
    single_request_timeout=300
)
organizations = dashboard.organizations.getOrganizations()
orgID = organizations[0]['id']
networks = dashboard.organizations.getOrganizationNetworks(orgID)

# Change this to True if you wish to backup your current sites variable and then get a new one
if False:
    # This is so our get_sites function can still get our client data easily
    shutil.copy('sites.pkl', 'sites.pkl.old')
    # This will be our actual historical copy that the code will never touch
    os.rename('sites.pkl', 'sites_' + str(int(time.time())) + '.pkl')

if os.path.isfile('sites.pkl'):
    sites = load_sites('sites.pkl')
else:
    sites = get_sites(dashboard, orgID, networks, get_clients=True)
    save_sites('sites.pkl', sites)
