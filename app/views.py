from flask import render_template, request
from app import app
from forms import PortchannelForm, PeeringForm, RtbhForm
from mycreds import *
from nxapi_light import *
import json, requests, re, threading
#from pycsco.nxos.device import Device
#from pycsco.nxos.utils.nxapi_lib import *
from collections import OrderedDict

requests.packages.urllib3.disable_warnings()

#global variable
ifaces = []
po_number = 1000


@app.before_first_request
def get_ifs_pos_shc3():

    def run_job():
        print "Run Job running"
        global ifaces 
        global po_number
        start = 300
        end = 400

        box = NXAPIClient(hostname="192.168.35.40", username = creds['user'], password = creds['passwd'])
        po_list = box.get_po_list(box.nxapi_call("show port-channel summary"))
        po_list = map(int, po_list)
        po_list = sorted(x for x in po_list if x >= start and x <= end)
        po_list = set(range(start,end)) - set(po_list)
        po_list = sorted(list(po_list))
        po_number = po_list[0]
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

        ifaces = [str(r) for r in ifaces]

    thread = threading.Thread(target=run_job)
    thread.start()

    print "IFACES: ", ifaces

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

@app.route('/',methods=['POST','GET'])
@app.route('/index', methods=['POST','GET'])
def index():

    return render_template('index.html', title='Home')

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
    
    if form.validate_on_submit():
        print "validated"
        first_request = False
        ipv4 = form.ipv4.data
        action = form.action.data
        
        try:
            if action:
                payload = "announce route " + ipv4 + "/32 next-hop 1.1.1.1 community [29405:666]"
            else: 
                payload = "withdraw route " + ipv4 + "/32 next-hop 1.1.1.1 community [29405:666]"

            data = {'command':payload}
            r = requests.post('http://192.168.8.3:5001/announce', data=data)
            response  = json.loads(r.text)
            status = peering_status()
            advertisement = route_advertisement()

        except:
            response = "Could not connect to API"

        return render_template('rtbh.html', title='RTBH', form=form, status=status, advertisement=advertisement)
    else:

        advertisement = route_advertisement()
        status = peering_status()


    
    return render_template('rtbh.html', title='RTBH', form=form, status=status, advertisement=advertisement)

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

@app.route('/po/<twins>', methods=['POST','GET'])
def portchannel(twins):

    return render_template('portchannel.html', twins = twins)

@app.route('/po/ajax_<twins>', methods=['POST','GET'])
def ajax_portchannel(twins):

    global ifaces 
    global po_number
    first_request = True
    twins = twins
    form = PortchannelForm()
    ids = [i for i in range(len(ifaces))]
    form.iface1.choices = form.iface2.choices = list(zip(ids, ifaces))
    portchannel = form.portchannel.data

    print form.data

    porttype = form.porttype.data
    location = form.location.data
    iface1_id = form.iface1.data
    
    print portchannel, porttype, location, iface1_id, twins

    if form.validate_on_submit():
        print "validated"
        first_request = False
        print portchannel, porttype, location, iface1_id
        portchannel = form.portchannel.data
        porttype = form.porttype.data
        location = form.location.data
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
        
        return render_template('ajax_portchannel.html', title='Portchannel', form=form, po_number=po_number, description=description, portchannel=portchannel, iface1=iface1, iface2 = iface2, trunk = porttype, twins = twins, first_request = first_request)
        
    else:
        clientid = 0
        print form.errors

    return render_template('ajax_portchannel.html', title='Portchannel', form=form, twins = twins, first_request=first_request)


