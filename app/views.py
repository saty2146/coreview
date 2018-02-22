from flask import render_template, request
from app import app
from forms import PortchannelForm, PeeringForm, RtbhForm, ScrubbingForm, PppoeForm, VxlanForm
from mycreds import *
from nxapi_light import *
import json, requests, re, threading, socket, sys, ssl, time
#from pycsco.nxos.device import Device
#from pycsco.nxos.utils.nxapi_lib import *
from collections import OrderedDict
from librouteros import login
logger.setLevel(logging.INFO)

requests.packages.urllib3.disable_warnings()

#global variable for portchannels SHC3 & DC4
ifaces_shc3 = []
po_number_shc3 = 1000
ifaces_dc4 = []
po_number_dc4 = 1000

ip_whitelist = ['81.89.63.129', '81.89.63.130', '81.89.63.131', '81.89.63.132', '81.89.63.133', '81.89.63.134', '81.89.63.135', '81.89.63.136', '81.89.63.137', '81.89.63.138', '81.89.63.139', '81.89.63.140', '81.89.63.141', '81.89.63.142', '81.89.63.143', '81.89.63.144', '81.89.63.145', '81.89.63.146', '81.89.63.147', '81.89.63.148', '81.89.63.149', '81.89.63.150', '127.0.0.1']


def valid_ip():
    client = request.remote_addr
    if client in ip_whitelist:
        return True
    else:
        return False

#@app.before_first_request
def get_ifaces_pos():

    def run_job(host):
        
        ifaces = []
        ip_box = boxes[host]['ip']
        
        if host == 'n31':
            start = 301
            end = 400
        else:
            start = 401
            end = 500

        box = NXAPIClient(hostname=ip_box, username = creds['user'], password = creds['passwd'])
        po_list = box.get_po_list(box.nxapi_call("show port-channel summary"))
        po_list = map(int, po_list)
        po_list = sorted(x for x in po_list if x >= start and x <= end)
        po_list = set(range(start,end)) - set(po_list)
        po_list = sorted(list(po_list))
        print "before request running"

        iface_status = box.get_iface_status(box.nxapi_call("show interface status"))
        
        iface_regex = re.compile(r".*({}).*".format('Ethernet'))

        for i in range(len(iface_status)):
            interface = iface_status[i]['interface']
            mo_iface = iface_regex.search(interface)
            if mo_iface:
                ifaces.append(interface)
            else:
                pass

        if host == 'n31':
            global ifaces_shc3 
            global po_number_shc3
            po_number_shc3 = po_list[0]
            ifaces_shc3 = [str(r) for r in ifaces]
        else:
            global ifaces_dc4
            global po_number_dc4
            po_number_dc4 = po_list[0]
            ifaces_dc4 = [str(r) for r in ifaces]

    thread = threading.Thread(target=run_job('n31'))
    thread.start()
    thread = threading.Thread(target=run_job('n41'))
    thread.start()

  #  return (ifaces, po_number)

def create_twin_dict(output1, output2):

    iface_status = OrderedDict() 

    for i in range(len(output1)):
        iface_dict1 = output1[i]
        iface_name = iface_dict1['interface']
        for key in iface_dict1.keys():
            newkey = key + "1"
            iface_dict1[newkey] = iface_dict1.pop(key)
        iface_status[iface_name] = iface_dict1
    
    for i in range(len(output2)):
        iface_dict2 = output2[i]
        iface_name = iface_dict2['interface']
        iface_status.setdefault(iface_name, {'speed':'100'})

        for key in iface_dict2.keys():
            newkey = key + "2"
            iface_dict2[newkey] = iface_dict2.pop(key)
        iface_status[iface_name].update(iface_dict2)
    
    return iface_status

def convert_mac(raw_list, mac_key):

    for arp in raw_list:
        if mac_key in arp:
            mac = str(arp[mac_key])
            mac = mac.translate(None, ".")
            mac = ':'.join(s.encode('hex') for s in mac.decode('hex'))
            arp[mac_key] = mac

    return raw_list

def peering_status():
    data = {'command':'show neighbor summary'}
    r = requests.post('http://192.168.8.3:5001/show_neighbor_summary', data=data)
    status  = json.loads(r.text)
    return status

def route_advertisement():
    data = {'command':'show adj-rib-out'}
    r = requests.post('http://192.168.8.3:5001/show_adj_rib_out', data=data)
    advertisement  = json.loads(r.text)
    return advertisement

def last_log():
    data = {'command':''}
    r = requests.post('http://192.168.8.3:5001/show_full_log', data=data)
    log  = json.loads(r.text)
    return log

@app.route('/',methods=['POST','GET'])
@app.route('/index', methods=['POST','GET'])
def index():

    if valid_ip():
        return render_template('index.html', title='Home')
    else:
        return render_template('404.html', title = 'Not Found')

@app.route('/port_status_tn3', methods=['POST','GET'])
def port_status_tn3():

    return render_template('port_status_tn3.html', title='Port Status SHC3')

@app.route('/port/<twins>', methods=['POST','GET'])
def port(twins):

    return render_template('port.html', twins = twins)

@app.route('/port/ajax_<twins>', methods=['POST','GET'])
def ajax_port(twins):
    
    hosts = pairs[twins]
    ip_box1 = boxes[hosts[0]]['ip']
    ip_box2 = boxes[hosts[1]]['ip']
    location = boxes[hosts[0]]['location']
    title = str(location) + " " + str(hosts[0]) + str(hosts[1])
    box1 = NXAPIClient(hostname = ip_box1, username = creds['user'], password = creds['passwd'])
    iface_box1 = box1.get_iface_status(box1.nxapi_call("show interface status"))
    box2 = NXAPIClient(hostname=ip_box2, username = creds['user'], password = creds['passwd'])
    iface_box2 = box2.get_iface_status(box2.nxapi_call("show interface status"))
    
    iface_status = create_twin_dict(iface_box1, iface_box2)

    return render_template('ajax_port.html', title=title, iface_status = iface_status, hosts = hosts, twins = twins, location = location)

@app.route('/port_host/<host>', methods=['POST','GET'])
def port_host(host):
    return render_template('port_host.html', host = host)

@app.route('/port_host/ajax_port_<host>', methods=['POST','GET'])
def ajax_port_host(host):
    
    ip_box = boxes[host]['ip']
    location = boxes[host]['location']
    title = str(location) + " " + str(host)
    box = NXAPIClient(hostname = ip_box, username = creds['user'], password = creds['passwd'])
    iface_status = box.get_iface_status(box.nxapi_call("show interface status"))
    
    return render_template('ajax_port_host.html', title=title, iface_status = iface_status, host = host, location = location)

@app.route('/arp/<host>', methods=['POST','GET'])
def arp(host):

    return render_template('arp.html', host = host)

@app.route('/arp/ajax_<host>', methods=['POST','GET'])
def ajax_arp(host):

    location = boxes[host]['location']
    title = str(location) + " " + str(boxes[host])
    ip = boxes[host]['ip']
    box = NXAPIClient(hostname=ip, username = creds['user'], password = creds['passwd'])
    arp_list = box.get_arp_list(box.nxapi_call("show ip arp"))
    arp_list = convert_mac(arp_list, 'mac')
    
    return render_template('ajax_arp.html', title=title, arp_list = arp_list, location = location, host = host)

@app.route('/mac/<host>', methods=['POST','GET'])
def mac(host):

    return render_template('mac.html', host = host)

@app.route('/mac/ajax_<host>', methods=['POST','GET'])
def ajax_mac(host):

    location = boxes[host]['location']
    title = str(location) + " " + str(boxes[host])
    ip = boxes[host]['ip']
    box = NXAPIClient(hostname=ip, username = creds['user'], password = creds['passwd'])
    mac_list = box.get_mac_list(box.nxapi_call("show mac address dynamic"))
    mac_list = convert_mac(mac_list, 'disp_mac_addr')
    
    return render_template('ajax_mac.html', title=title, mac_list = mac_list, location = location, host = host)

@app.route('/rtbh', methods=['POST','GET'])
def rtbh():
    form = RtbhForm()
    
    if form.validate_on_submit():
        print "validated"
        first_request = False
        ipv4 = form.ipv4.data
        action = form.action.data
        
        try:
            if action:
                payload = "neighbor 109.74.150.18 announce route " + ipv4 + "/32 next-hop 1.1.1.1 community [29405:666]"
            else: 
                payload = "neighbor 109.74.150.18 withdraw route " + ipv4 + "/32 next-hop 1.1.1.1 community [29405:666]"

            data = {'command':payload}
            r = requests.post('http://192.168.8.3:5001/announce', data=data)
            response  = json.loads(r.text)
            status = peering_status()
            advertisement = route_advertisement()
            log = last_log()

        except:
            response = "Could not connect to API"

        return render_template('rtbh.html', title='RTBH', form=form, status=status, advertisement=advertisement, log=log)
    else:

        advertisement = route_advertisement()
        status = peering_status()
        log = last_log()

    return render_template('rtbh.html', title='RTBH', form=form, status=status, advertisement=advertisement, log=log)

@app.route('/scrubbing', methods=['POST','GET'])
def scrubbing():
    form = ScrubbingForm()
    
    if form.validate_on_submit():
        print "validated"
        first_request = False
        action = form.action.data
        network_id = form.network.data
        network = [f[1] for f in form.network.choices if f[0] == network_id]
        network = network[0]

        if action:
            payload = "neighbor 109.74.147.190 announce route " + network + " next-hop 1.1.1.1 community [29405:778]"
        else: 
            payload = "neighbor 109.74.147.190 withdraw route " + network + " next-hop 1.1.1.1 community [29405:778]"

        try:
            data = {'command':payload}
            r = requests.post('http://192.168.8.3:5001/announce', data=data)
            response  = json.loads(r.text)
            status = peering_status()
            advertisement = route_advertisement()
            log = last_log()

        except:
            response = "Could not connect to API"

        return render_template('scrubbing.html', title='Scrubbing', form=form, status=status, advertisement=advertisement, log=log)
    else:

        advertisement = route_advertisement()
        status = peering_status()
        log = last_log()

    return render_template('scrubbing.html', title='Scrubbing', form=form, status=status, advertisement=advertisement,log=log)

def pppoe_status(pppoe):
   
    status = {}
    gw_status  = {}
    for k,v in pppoe_gws.iteritems():
        gw = k
        ip = v
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (ip, 8728)
        sock.settimeout(5.0)

        try:
            sock.connect(server_address)
            api = login(username='api', password='apina', sock=sock)
            #params = {'.proplist':('type,.id,name,mac-address')}
            #result = api(cmd='/interface/print', **params)
            #result = api(cmd='/interface/pppoe-server/print')
        except socket.error, exc:
            print "Socket error: %s" % exc
            gw_status[gw] = 'Socket error'
            continue
        
        try:
            result = api(cmd='/ppp/active/print')
        except:
            gw_status[gw] = 'API error'
            print "API error"
            print result
            continue
       
        sock.close()

        gw_status[gw] = 'OK'

        for acc in result: 
            if acc['name'] == pppoe:
                status = acc
                break
        else:
            time.sleep(0.2)
            continue
        break

    print status, gw, gw_status

    return (status, gw, gw_status)

def pppoe_get_vendor(mac):
    MAC_URL = 'http://macvendors.co/api/%s'
    r = requests.get(MAC_URL % mac)
    r = r.json()
    r = r['result']
    print r
    
    if 'error' not in r:
        mac = r['company'] 
    else:
        mac = None
    return mac

@app.route('/pppoe', methods=['POST','GET'])
def pppoe():
    form = PppoeForm()
    first_request = True
    mac_address = None
    vendor = None

    if form.validate_on_submit():
        print "validated"
        first_request = False
        pppoe = form.pppoe.data
        status, gw, gw_status = pppoe_status(pppoe)
        if status:
            #mac_address = status['remote-address']
            mac_address = status['caller-id']
            vendor = pppoe_get_vendor(mac_address)
        return render_template('pppoe.html', title='Pppoe', form=form, status=status, gw=gw, gw_status = gw_status, vendor=vendor, first_request = first_request)

    return render_template('pppoe.html', title='Pppoe', form=form, first_request = first_request)

@app.route('/pppoejq', methods=['POST','GET'])
def pppoejq():
    form = PppoeForm()
    return render_template('jquery.html')

@app.route('/peering', methods=['POST','GET'])
def peering():
    form = PeeringForm()
    first_request = True
    peers = {1:['six','ipv6-six'],2:['nix.cz','ipv6-nix.cz'],3:['nix.sk','ipv6-nix.sk'],4:['AMS-IX-IPV4','AMS-IX-IPV6']}

    if form.validate_on_submit():
        print "validated"
        first_request = False
        peering = form.peering.data
        peergroup = [peers[f] for f in peers if f == peering]
        print peergroup
        return render_template('peering.html', title='Peering', form=form, peergroup=peergroup, first_request = first_request)

    return render_template('peering.html', title='Peering', form=form, first_request = first_request)

def get_vxlan_data(vlanid):
    vlanidhex = bin(vlanid)[2:].zfill(16)
    octet1 = int(vlanidhex[:8], 2)
    octet2 = int(vlanidhex[8:], 2)
    return (octet1, octet2)

@app.route('/vxlan', methods=['POST','GET'])
def vxlan():
    form = VxlanForm()
    first_request = True
    vxlan_data = {}

    if form.validate_on_submit():
        print "validated"
        first_request = False
        vlanid = form.vlanid.data
        vni = 10000 + int(vlanid )
        octet1, octet2 = get_vxlan_data(vlanid)
        vxlan_data['octet1'] = octet1
        vxlan_data['octet2'] = octet2
        vxlan_data['vni'] = vni

        return render_template('vxlan.html', title='Vxlan', form=form, vxlan_data = vxlan_data, first_request = first_request)

    return render_template('vxlan.html', title='Vxlan', form=form, first_request = first_request)

@app.route('/po/<twins>', methods=['POST','GET'])
def portchannel(twins):
    
    global ifaces_shc3
    global po_number_shc3
    global ifaces_dc4
    global po_number_dc4

    if twins == 'tn3':
        ifaces = ifaces_shc3
        po_number = po_number_shc3
        location = 'SHC3'
    else: 
        ifaces = ifaces_dc4
        po_number = po_number_dc4
        location = 'DC4'

    first_request = True
    twins = twins
    form = PortchannelForm()
    ids = [i for i in range(len(ifaces))]
    form.iface1.choices = form.iface2.choices = list(zip(ids, ifaces))
    portchannel = form.portchannel.data

    print form.data

    porttype = form.porttype.data
    iface1_id = form.iface1.data
    
    print portchannel, porttype, location, iface1_id, twins

    if form.validate_on_submit():
        print "validated"
        first_request = False
        print portchannel, porttype, location, iface1_id
        portchannel = form.portchannel.data
        porttype = form.porttype.data
        iface1_id = form.iface1.data
        iface2_id = form.iface2.data
        clientid = form.clientid.data
        company = form.company.data
        vlans = form.vlans.data

        iface1 = [f[1] for f in form.iface1.choices if f[0] == iface1_id]
        iface2 = [f[1] for f in form.iface2.choices if f[0] == iface2_id]
        iface1 = iface1[0]
        iface2 = iface2[0]
        
        description = str(clientid) + "-" + company
        
        form.clientid.data = clientid
        
        return render_template('portchannel.html', title='Portchannel', form=form, po_number=po_number, description=description, location=location, portchannel=portchannel, iface1=iface1, iface2 = iface2, trunk = porttype, twins = twins, first_request = first_request)
        
    else:
        clientid = 0
        print form.errors

    return render_template('portchannel.html', title='Portchannel', form=form, twins = twins, location = location, first_request=first_request)


@app.route('/ifsw/<host>/<path:iface>', methods=['POST','GET'])
def ifsw(host, iface):

    ip = boxes[host]['ip']
    box = NXAPIClient(hostname=ip, username = creds['user'], password = creds['passwd'])
    ifsw = box.get_iface_switchport(box.nxapi_call("show interface " + iface + " switchport" ))
    

    return render_template('iface_switchport.html', title='Interface switchport configuration', iface=iface, host=host, ifsw=ifsw) 

@app.route('/iferr/<host>/<path:iface>', methods=['POST','GET'])
def iferr(host, iface):

    ip = boxes[host]['ip']
    box = NXAPIClient(hostname=ip, username = creds['user'], password = creds['passwd'])
    iferr = box.get_iface_errors(box.nxapi_call("show interface " + iface + " counters errors" ))

    return render_template('iface_errors.html', title='Interface errors', iface=iface, host=host, iferr=iferr) 
