from flask import render_template, request, flash, redirect, url_for, jsonify
from app import app
from forms import PortchannelForm, PeeringForm, RtbhForm, ScrubbingForm, PppoeForm, VxlanForm, DateForm, DslForm, L2circuitForm, RouteForm, VlanForm, FPVlanForm
from mycreds import *
from nxapi_light import *
import json, requests, re, threading, socket, sys, ssl, time, os.path, yaml
from collections import OrderedDict
from librouteros import login
logger.setLevel(logging.INFO)
import datetime, glob
from elasticsearch import Elasticsearch
import copy

requests.packages.urllib3.disable_warnings()

ip_whitelist = ['81.89.63.129',
                '81.89.63.130',
                '81.89.63.131',
                '81.89.63.132',
                '81.89.63.133',
                '81.89.63.134',
                '81.89.63.135',
                '81.89.63.136',
                '81.89.63.137',
                '81.89.63.138',
                '81.89.63.139',
                '81.89.63.140',
                '81.89.63.141',
                '81.89.63.142',
                '81.89.63.143',
                '81.89.63.144',
                '81.89.63.145',
                '81.89.63.146',
                '81.89.63.147',
                '81.89.63.148',
                '81.89.63.149',
                '81.89.63.150',
                '127.0.0.1'
                ]


def load_config():
    with open('app/config.yml', 'r') as f:
        conf = yaml.safe_load(f)
        boxes = conf['boxes']
        pairs = conf['pairs']
        pppoe_gws = conf['pppoe_gws']

    return(conf, boxes, pairs, pppoe_gws)

conf, boxes, pairs, pppoe_gws = load_config()

def load_iff_errs():
    resource_path = os.path.join(app.root_path)
    os.chdir(resource_path)

    with open('ifaces_core_errs.yml', 'r') as f:
        ifaces = yaml.safe_load(f)

    return ifaces

conf, boxes, pairs, pppoe_gws = load_config()

def valid_ip():
    client = request.remote_addr
    if client in ip_whitelist:
        return True
    else:
        return False

def get_ifaces_pos(host):

    ifaces = []
    ip_box = boxes[host]['ip']
    
    if host == 'n31':
        start = 301
        end = 400
    else:
        start = 401
        end = 500

    box = NXAPIClient(hostname=ip_box, username = USERNAME, password = PASSWORD)
    po_list = box.get_po_list(box.nxapi_call(["show port-channel summary"]))
    po_list = map(int, po_list)
    po_list = sorted(x for x in po_list if x >= start and x <= end)
    po_list = set(range(start,end)) - set(po_list)
    po_list = sorted(list(po_list))
    print "before request running"

    iface_status = box.get_iface_status(box.nxapi_call(["show interface status"]))

    for item in iface_status:
        key = item['interface']
        value = item['state']
        
        if value == 'connected':
            value = 'Up'
        else:
            value = 'Down'

        key_value = key + ' ' + value
        iface_regex = re.compile(r".*({}).*".format('Ethernet'))
        mo_iface = iface_regex.search(key)
        if mo_iface:
            ifaces.append(key_value)
        else:
            pass

        po_number = po_list[0]

    return (ifaces, po_number)

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

def conf_cleaner(raw_conf):
    clean_conf = raw_conf.replace('\r', '')  # delete '\r'
    clean_conf = clean_conf.split('\n')  # split
    clean_conf = list(map(str, clean_conf))  # delete whitespaces items
    clean_conf = list(map(str.strip, clean_conf))  # stripping
    clean_conf = list(filter(str.strip, clean_conf))
    clean_conf = [elem for elem in clean_conf if elem != '!' and elem != 'end' and elem != 'configure terminal']
    return clean_conf

@app.route('/',methods=['POST','GET'])
@app.route('/index', methods=['POST','GET'])
def index():

    if valid_ip():
        return render_template('index.html', title='Home', conf=conf)
    else:
        return render_template('404.html', title = 'Not Found')

@app.route('/',methods=['POST','GET'])
@app.route('/contact', methods=['POST','GET'])
def contact():

    if valid_ip():
        return render_template('contact.html', title='Contact', conf=conf)
    else:
        return render_template('404.html', title = 'Not Found')

@app.route('/port_status_tn3', methods=['POST','GET'])
def port_status_tn3():

    return render_template('port_status_tn3.html', title='Port Status SHC3', conf=conf)

@app.route('/port/<twins>', methods=['POST','GET'])
def port(twins):
    return render_template('port.html', twins = twins, conf=conf)

@app.route('/port/ajax_<twins>', methods=['POST','GET'])
def ajax_port(twins):
    
    hosts = pairs[twins]['members']
    ip_box1 = boxes[hosts[0]]['ip']
    ip_box2 = boxes[hosts[1]]['ip']
    location = boxes[hosts[0]]['location']
    title = str(location) + " " + str(hosts[0]) + str(hosts[1])
    box1 = NXAPIClient(hostname = ip_box1, username = USERNAME, password = PASSWORD)
    iface_box1 = box1.get_iface_status(box1.nxapi_call(["show interface status"]))
    box2 = NXAPIClient(hostname=ip_box2, username = USERNAME, password = PASSWORD)
    iface_box2 = box2.get_iface_status(box2.nxapi_call(["show interface status"]))
    
    iface_status = create_twin_dict(iface_box1, iface_box2)

    return render_template('ajax_port.html', title=title, iface_status = iface_status, hosts = hosts, twins = twins, location = location)

@app.route('/port_host/<host>', methods=['POST','GET'])
def port_host(host):
    return render_template('port_host.html', host=host, conf=conf)

@app.route('/port_host/ajax_port_<host>', methods=['POST','GET'])
def ajax_port_host(host):
    
    ip_box = boxes[host]['ip']
    location = boxes[host]['location']
    title = str(location) + " " + str(host)
    box = NXAPIClient(hostname = ip_box, username = USERNAME, password = PASSWORD)
    iface_status = box.get_iface_status(box.nxapi_call(["show interface status"]))
    
    return render_template('ajax_port_host.html', title=title, iface_status = iface_status, host = host, location = location)

def merge_sfp_iface(l1, l2, key):
    merged = {}
    for item in l1+l2:
        if item[key] in merged:
            merged[item[key]].update(item)
        else:
            merged[item[key]] = item
    return [val for (_, val) in merged.items()]

@app.route('/sfp/<host>', methods=['POST','GET'])
def sfp(host):
    return render_template('sfp.html', host=host, conf=conf)

@app.route('/sfp/ajax_sfp_<host>', methods=['POST','GET'])
def ajax_sfp_host(host):
    
    ip_box = boxes[host]['ip']
    location = boxes[host]['location']
    title = str(location) + " " + str(host)
    box = NXAPIClient(hostname = ip_box, username = USERNAME, password = PASSWORD)
    sfp_details = box.get_all_transceiver_details(box.nxapi_call(["show interface transceiver details"]))
    sfp_desc = box.get_iface_description(box.nxapi_call(["show interface description"]))
    sfp_status = merge_sfp_iface(sfp_desc, sfp_details, 'interface')

    return render_template('ajax_sfp.html', title=title, sfp_status = sfp_status, host = host, location = location, conf=conf)

@app.route('/arp/<host>', methods=['POST','GET'])
def arp(host):
    return render_template('arp.html', host=host, conf=conf)

@app.route('/arp/ajax_<host>', methods=['POST','GET'])
def ajax_arp(host):

    location = boxes[host]['location']
    title = str(location) + " " + str(boxes[host])
    ip = boxes[host]['ip']
    box = NXAPIClient(hostname=ip, username = USERNAME, password = PASSWORD)
    arp_list = box.get_arp_list(box.nxapi_call(["show ip arp"]))
    arp_list = convert_mac(arp_list, 'mac')
    
    return render_template('ajax_arp.html', title=title, arp_list = arp_list, location = location, host = host)

@app.route('/mac/<host>', methods=['POST','GET'])
def mac(host):

    return render_template('mac.html', host=host, conf=conf)

@app.route('/mac/ajax_<host>', methods=['POST','GET'])
def ajax_mac(host):

    location = boxes[host]['location']
    title = str(location) + " " + str(boxes[host])
    ip = boxes[host]['ip']
    box = NXAPIClient(hostname=ip, username = USERNAME, password = PASSWORD)
    mac_list = box.get_mac_list(box.nxapi_call(["show mac address dynamic"]))
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
                payload = "neighbor 109.74.150.18 announce route " + ipv4 + "/32 next-hop 192.0.2.1 community [29405:666]"
            else: 
                payload = "neighbor 109.74.150.18 withdraw route " + ipv4 + "/32 next-hop 192.0.2.1 community [29405:666]"

            data = {'command':payload}
            r = requests.post('http://192.168.8.3:5001/announce', data=data)
            response  = json.loads(r.text)
            status = peering_status()
            advertisement = route_advertisement()
            log = last_log()

        except:
            response = "Could not connect to API"

        return render_template('rtbh.html', title='RTBH', form=form, status=status, advertisement=advertisement, log=log, conf=conf)
    else:

        advertisement = route_advertisement()
        status = peering_status()
        log = last_log()

    return render_template('rtbh.html', title='RTBH', form=form, status=status, advertisement=advertisement, log=log, conf=conf)

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
            payload = "neighbor 109.74.147.190 announce route " + network + " next-hop 192.0.2.1 community [29405:778]"
        else: 
            payload = "neighbor 109.74.147.190 withdraw route " + network + " next-hop 192.0.2.1 community [29405:778]"

        try:
            data = {'command':payload}
            r = requests.post('http://192.168.8.3:5001/announce', data=data)
            response  = json.loads(r.text)
            status = peering_status()
            advertisement = route_advertisement()
            log = last_log()

        except:
            response = "Could not connect to API"

        return render_template('scrubbing.html', title='Scrubbing', form=form, status=status, advertisement=advertisement, log=log, conf=conf)
    else:

        advertisement = route_advertisement()
        status = peering_status()
        log = last_log()

    return render_template('scrubbing.html', title='Scrubbing', form=form, status=status, advertisement=advertisement,log=log, conf=conf)

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
            params = {'.proplist':('.id,name,address,caller-id,uptime,service')}
            result = api(cmd='/ppp/active/print', **params)
           # result = api(cmd='/ip/firewall/service-port/print')
        except:
            gw_status[gw] = 'API error'
            print "API error"
            continue

        gw_status[gw] = 'OK'

        for acc in result: 
            if acc['name'] == pppoe:
                status = acc
                params = {'.proplist':('target,max-limit')}
                queues = api(cmd='/queue/simple/print', **params)
                for queue in queues:
                    target = '<pppoe-' + pppoe + '>'
                    if queue['target'] == target:
                        shape_up_down =  queue['max-limit'].split("/")
                        shape = str(int(shape_up_down[0])/1000000) + 'M' + ' / ' + str(int(shape_up_down[1])/1000000) + 'M'
                        status['shape'] = shape
                break
        else:
            time.sleep(0.2)
            sock.close()
            continue
        break

        sock.close()

    return (status, gw, gw_status)

def terminate_pppoe(gw, id_rule):
    result = False
    for k, v in pppoe_gws.iteritems():
        if k == gw:
            ip = v
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (ip, 8728)
    sock.settimeout(5.0)

    try:
        sock.connect(server_address)
        api = login(username='api', password='apina', sock=sock)

    except socket.error, exc:
        print "Socket error: %s" % exc

    try:
        if api is not None:
            params = {'.id': id_rule}
            result = api(cmd='/ppp/active/remove', **params)
            print result
    except:
        print "API error"

    return result

def pppoe_get_vendor(mac):
    MAC_URL = 'http://macvendors.co/api/%s'
    r = requests.get(MAC_URL % mac)
    r = r.json()
    r = r['result']

    if 'error' not in r:
        mac = r['company'] 
    else:
        mac = None
    return mac

def create_query_log(id_pppoe):

    query = {
      "query": {
        "bool": {
          "must": [
            {
              "match": {
                "sysloghost": "radiusint1*"
              }
            },
            {
              "match_phrase": {
                "message": id_pppoe
              }
            },
            {
              "range": {
                "@timestamp": {
                  "time_zone": "+02:00",
                  "gte": "now-14d",
                  "lt": "now"
                }
              }
            }
          ]
        }
      },
      "sort": {
        "@timestamp": "desc"
      }
    }

    return query

def pppoe_get_log(pppoe, query):

    es = Elasticsearch([{'host': '192.168.35.225', 'port': 9200}])
    try:
        query = es.search(body=query, request_timeout=30, size=50 )
        log = [doc for doc in query['hits']['hits']]
    except Exception:
        log = [{'_source': { 'message': 'ConnectionTimeout. Try again'}}]

    return log

@app.route('/ftth', methods=['POST','GET'])
def ftth():
    form = PppoeForm()
    first_request = True
    mac_address = None
    vendor = None
    log = None

    if form.validate_on_submit():
        print "validated"
        first_request = False
        if request.form['action'] == 'search':
            print "Search"
            pppoe = form.pppoe.data
            id_pppoe, realm = pppoe.split("@")
            status, gw, gw_status = pppoe_status(pppoe)

            if status:
                mac_address = status['caller-id']
                vendor = pppoe_get_vendor(mac_address)
                query_log = create_query_log(pppoe)
                log = pppoe_get_log(pppoe, query_log)
            else:
                # get log even if account is not found (aka auth failure:)
                query_log = create_query_log(pppoe)
                log = pppoe_get_log(pppoe, query_log)

            return render_template('ftth.html', title='Ftth', form=form, status=status, gw=gw, gw_status = gw_status, vendor=vendor, log = log, first_request = first_request,conf=conf)
        else:
             print "Terminating ..."
             id_rule = request.form['id']
             gw = request.form['gw']
             pppoe = request.form['pppoe']
             result = terminate_pppoe(gw, id_rule)
             #if result_box1 and result_box2:
             flash(pppoe + ' has been terminated')
             return redirect(url_for('ftth'))


    return render_template('ftth.html', title='Ftth', form=form, first_request = first_request, conf=conf)

@app.route('/dsl', methods=['POST','GET'])
def dsl():
    form = DslForm()
    first_request = True
    log = None

    if form.validate_on_submit():
        print "validated"
        first_request = False
        dsl = form.dsl.data
        id_dsl, realm = dsl.split("@")

        query_log = create_query_log(dsl)
        log = pppoe_get_log(dsl, query_log)

        return render_template('dsl.html', title='Dsl', form=form, log = log, first_request = first_request, conf=conf)

    return render_template('dsl.html', title='Dsl', form=form, first_request = first_request, conf=conf)

@app.route('/route', methods=['POST','GET'])
def route():
    form = RouteForm()
    first_request = True
    host = 'n931'

    if form.validate_on_submit():
        print "validated"
        first_request = False
        route = form.route.data
        ip_box = boxes[host]['ip']
        box = NXAPIClient(hostname=ip_box, username=USERNAME, password=PASSWORD)
        result = box.get_ip_route(box.nxapi_call(["show ip route " + route]))
        print result

        return render_template('route.html', title='Route', form=form, result=result, host=host, first_request = first_request, conf=conf)

    return render_template('route.html', title='Route', form=form, first_request = first_request, conf=conf)

@app.route('/vlanid', methods=['POST','GET'])
def vlanid():
    form = VlanForm()
    first_request = True
    host = 'n31'

    if form.validate_on_submit():
        print "validated"
        first_request = False
        vlanid = form.vlanid.data
        ip_box = boxes[host]['ip']
        box = NXAPIClient(hostname=ip_box, username=USERNAME, password=PASSWORD)
        result = box.get_vlan_id(box.nxapi_call(["show vlan id " + str(vlanid)]))
        print result

        return render_template('vlanid.html', title='Vlan', form=form, result=result, host=host, first_request = first_request, conf=conf)

    return render_template('vlanid.html', title='Vlan', form=form, first_request = first_request, conf=conf)

@app.route('/fpvlan', methods=['POST','GET'])
def fpvlan():
    form = FPVlanForm()
    first_request = True
    hosts = ['n31','n32','n41','n42']

    if form.validate_on_submit():
        print "validated"
        first_request = False

        if request.form['action'] == 'Generate':
            print "Generate"
            vlanid = form.vlanid.data
            vlanname = form.vlanname.data
            for host in hosts:
                ip_box = boxes[host]['ip']
                box = NXAPIClient(hostname=ip_box, username=USERNAME, password=PASSWORD)
                result = box.get_vlan_id(box.nxapi_call(["show vlan id " + str(vlanid)]))
                if result:
                    flash('Vlan already exists')
                    break
                print result

            return render_template('fpvlan.html', title='FPVlan', form=form, result=result, vlanid=vlanid, vlanname=vlanname, host=host, first_request = first_request, conf=conf)

        else:
            print "Deploy"
            fp_conf = request.form['configuration.data']
            # data cleaner, config list creation
            fp_conf = conf_cleaner(request.form['configuration.data'])
            print fp_conf
            for host in hosts:
                ip_box = boxes[host]['ip']
                box = NXAPIClient(hostname=ip_box, username=USERNAME, password=PASSWORD)
                result = box.set_cmd(box.nxapi_call(fp_conf))
                if result:
                    flash_ok = True

            if flash_ok:
                flash('Deployment has been successfull')
            else:
                flash('Something is wrong')

            return redirect(url_for('fpvlan'))

    return render_template('fpvlan.html', title='FPVlan', form=form, first_request = first_request, conf=conf)

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
        return render_template('peering.html', title='Peering', form=form, peergroup=peergroup, first_request = first_request, conf=conf)

    return render_template('peering.html', title='Peering', form=form, first_request = first_request, conf=conf)

@app.route('/l2circuit', methods=['POST','GET'])
def l2circuit():
    form = L2circuitForm()
    first_request = True

    if form.validate_on_submit():
        print "validated"
        first_request = False
        iface_id = form.iface.data
        vlan = form.vlan.data
        clientid = form.clientid.data
        company = form.company.data
        circuit_type = form.circuit_type.data
        description = str(clientid) + "-" + company
        iface = [f[1] for f in form.iface.choices if f[0] == iface_id]
        iface = iface[0]
        return render_template('l2circuit.html', title='L2circuit', form=form, circuit_type=circuit_type, iface=iface, vlan=vlan, description=description, first_request = first_request, conf=conf)

    return render_template('l2circuit.html', title='L2circuit', form=form, first_request = first_request, conf=conf)

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

        return render_template('vxlan.html', title='Vxlan', form=form, vxlan_data = vxlan_data, first_request = first_request,conf=conf)

    return render_template('vxlan.html', title='Vxlan', form=form, first_request = first_request, conf=conf)

@app.route('/po/<twins>', methods=['POST','GET'])
def po(twins):
    
    if twins == 'tn3':
        ifaces, po_number = get_ifaces_pos("n31")
        ifaces = ifaces[48:]    #remove parent ports from list (Ethernet1/1-48)
        location = 'SHC3'
    else: 
        ifaces, po_number = get_ifaces_pos("n41")
        ifaces = ifaces[64:]    #remove parent ports from list (Ethernet1/1-48, Ethernet3/1-16,)
        location = 'DC4'

    first_request = True
    twins = twins
    form = PortchannelForm()
    ids = [i for i in range(len(ifaces))]
    form.iface1.choices = form.iface2.choices = list(zip(ids, ifaces))
    portchannel = form.portchannel.data

    porttype = form.porttype.data
    iface1_id = form.iface1.data
    
    if form.validate_on_submit():
        print "validated"
        first_request = False
        print portchannel, porttype, location, iface1_id
        #dummy_conf = ["interface Eth131/1/1", "non shutdown", "interface Eth131/1/2", "shutdown"]

        if request.form['action'] == 'Generate':
            print "Generate"
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

            return render_template('portchannel.html', title='Portchannel', form=form, po_number=po_number, description=description, location=location, portchannel=portchannel, iface1=iface1, iface2 = iface2, trunk = porttype, vlans=vlans, twins = twins, first_request = first_request, conf=conf)
        else:
            print "Deploy"
            # data cleaner, config list creation
            po_conf = request.form['configuration.data']
            po_conf = po_conf.replace('\r', '')     #delete '\r'
            po_conf = po_conf.split('\n')           #split
            po_conf = list(map(str, po_conf))       #delete whitespaces items
            po_conf = list(map(str.strip, po_conf)) #stripping
            po_conf = list(filter(str.strip, po_conf))
            po_conf = [ elem for elem in po_conf  if elem != '!' and elem != 'end' and elem != 'configure terminal']

            hosts = pairs[twins]['members']
            ip_box1 = boxes[hosts[0]]['ip']
            ip_box2 = boxes[hosts[1]]['ip']
            box1 = NXAPIClient(hostname = ip_box1, username = USERNAME, password = PASSWORD)
            result_box1 = box1.set_cmd(box1.nxapi_call(po_conf))
            box2 = NXAPIClient(hostname=ip_box2, username = USERNAME, password = PASSWORD)
            result_box2 = box2.set_cmd(box2.nxapi_call(po_conf))

            if result_box1 and result_box2:
                flash('Deployment has been successfull')
            else:
                flash('Something is wrong')

            return redirect(url_for('po', twins = twins))

    else:
        clientid = 0
        print form.errors

    return render_template('portchannel.html', title='Portchannel', form=form, twins = twins, location = location, first_request=first_request, conf=conf)

@app.route('/ifsw/<host>/<path:iface>', methods=['POST','GET'])
def ifsw(host, iface):

    ip = boxes[host]['ip']
    box = NXAPIClient(hostname=ip, username = USERNAME, password = PASSWORD)
    ifsw = box.get_iface_switchport(box.nxapi_call(["show interface " + iface + " switchport"]))
    ifsw = json.dumps(ifsw)
    print ifsw

    return ifsw
    

    #return render_template('iface_switchport.html', title='Interface switchport configuration', iface=iface, host=host, ifsw=ifsw, conf=conf)

@app.route('/iferr/<host>/<path:iface>', methods=['POST','GET'])
def iferr(host, iface):

    ip = boxes[host]['ip']
    box = NXAPIClient(hostname=ip, username = USERNAME, password = PASSWORD)
    iferr = box.get_iface_errors(box.nxapi_call(["show interface " + iface + " counters errors"]))
    iferr = json.dumps(iferr)

    return iferr
    #return render_template('iface_errors.html', title='Interface errors', iface=iface, host=host, iferr=iferr, conf=conf)

@app.route('/logs', methods=['POST','GET'])
def logs():
    form = DateForm()
    ids = [i for i in range(len(boxes))]
    form.box.choices = list(zip(ids, boxes))

    if form.validate_on_submit():
        print("validated")
        dt = str(form.dt.data)
        date = dt.replace('-','')
        box_id = form.box.data
        box = [f[1] for f in form.box.choices if f[0] == box_id]
        severity_id = form.severity.data
        severity = [f[1] for f in form.severity.choices if f[0] == severity_id]
        payload = { 'date':date, 'severity':severity, 'box':box }
        r = requests.get('http://217.73.28.16:5002/syslog', params=payload)
        print(r.url)
        logs  = json.loads(r.text)

        return render_template('logs.html', logs=logs, form=form, conf=conf) 
        
    else:
        date = datetime.datetime.now().strftime ("%Y%m%d")
        # Uncomment if you want to allow default view
        #severity = all
        #box = six
        #payload = { 'date':date, 'severity':severity, 'box':box }
        #r = requests.get('http://217.73.28.16:5002/syslog', params=payload)
        #logs  = json.loads(r.text)

        logs  = {}
        return render_template('logs.html', logs=logs, form=form, conf=conf)

def get_vlan(nxhosts):
    '''
    Walk through json vlan-db files  located in vlan-db directory (created by cronjob) and create dictionary in format:

    vlan = {vlanid1: { box1_name: name,
                       box1_state: state,
                       box1_mode: mode,
                       box2name: name,
                       box2_state: state,
                       box2_mode: mode,
                       ...
                     }
            vlanid2: { box1_name: name,
                       box1_state: state,
                       box1_mode: mode,
                       box2name: name,
                       box2_state: state,
                       box2_mode: mode,
                       ...
                       }
    }
    :return:(vlan, key_attributes, file_created)
    '''

    vlan = {}
    boxes = []
    vlan_attr = ['N', 'S', 'M']

    resource_path = os.path.join(app.root_path, 'vlan-db' + '/' + nxhosts)
    os.chdir(resource_path)

    if nxhosts == 'n5k':
        created = time.ctime(os.path.getctime('n31-vlan-db.json'))
    elif nxhosts == 'n9k':
        created = time.ctime(os.path.getctime('n911-vlan-db.json'))
    else:
        pass

    for filename in glob.glob("*.json"):
        box = filename.split("-")
        box = box[0]
        boxes.append(box)

    box_attr = [str(_box) + '_' + str(_attr) for _attr in vlan_attr for _box in boxes]

    for filename in glob.glob("*.json"):
        box = filename.split("-")
        box = box[0]
        with open(filename) as file:
            data = json.load(file)
            vlan_brief = data['TABLE_vlanbrief']['ROW_vlanbrief']
            vlan_mode = data['TABLE_mtuinfo']['ROW_mtuinfo']

            for item in vlan_brief:
                vlanid = item['vlanshowbr-vlanid']
                vlanname = item['vlanshowbr-vlanname']
                vlanstate = item['vlanshowbr-vlanstate']

                vlanname_key = str(box) + '_' + 'N'
                vlanstate_key = str(box) + '_' + 'S'

                vlan.setdefault(vlanid,{str(_box) + '_' + str(_attr):'Error' for _attr in vlan_attr if _attr == 'N' for _box in boxes})

                vlan[vlanid][vlanname_key] = vlanname
                vlan[vlanid][vlanstate_key] = vlanstate
            for item in vlan_mode:
                vlanid = item['vlanshowinfo-vlanid']
                _vlanmode = item['vlanshowinfo-vlanmode']
                if _vlanmode == 'fabricpath-vlan':
                    vlanmode = 'FP'
                elif  _vlanmode == 'ce-vlan':
                    vlanmode = 'CE'
                else:
                    pass

                vlanmode_key = str(box) + '_' + 'M'
                vlan[vlanid][vlanmode_key] = vlanmode

    return (vlan, box_attr, created)

@app.route('/vlan/<nxhosts>', methods=['POST','GET'])
def vlan(nxhosts):


    vlan, box_attr, created = get_vlan(nxhosts)

    return render_template('vlan.html', vlan=vlan, box_attr = box_attr, created = created, nxhosts = nxhosts, conf=conf )

def create_iff_errs_diff(ifaces_new, ifaces_cur):

    ifaces = copy.deepcopy(ifaces_new)

    for k, v in ifaces_new.iteritems():
        for in_k, in_v in v.iteritems():
            if in_k != 'interface' and in_k != 'type' and in_k != 'speed' and in_k != 'desc':
                k_diff = str(in_k) + '_diff'
                v_diff = int(ifaces_new[k][in_k]) - int(ifaces_cur[k][in_k])
            ifaces[k][k_diff] = v_diff

    return ifaces

@app.route('/iferrs', methods=['POST','GET'])
def iferrs():
    ifaces_all = load_iff_errs()
    ifaces_new = {}
    ifaces_cur = {}
    result = {}

    resource_path = os.path.join(app.root_path, 'iface-err')
    iface_desc_path = os.path.join(app.root_path, 'iface-desc')

    for box in ifaces_all:

        if (os.path.isdir(resource_path)):
            os.chdir(resource_path)

            file_new = box + '-iface-err-new.json'
            file_cur = box + '-iface-err-cur.json'
            file_desc = box + '-iface-desc.json'
            
            if (os.path.exists(file_new)) and (os.path.exists(file_cur)):
                created_new = time.ctime(os.path.getmtime(file_new))
                created_cur = time.ctime(os.path.getmtime(file_cur))

                with open(file_new) as file_n:
                    data_n = json.load(file_n)
                    data_n = data_n['TABLE_interface']['ROW_interface']
                    data_n = [item for item in data_n if 'eth_fcs_err' in item]

                with open(iface_desc_path + '/' + file_desc) as file_d:
                    data_d = json.load(file_d)
                    data_d = data_d['TABLE_interface']['ROW_interface']

                data = merge_sfp_iface(data_n, data_d, 'interface')

                for item in data:
                    if item['interface'] in ifaces_all[box] and 'eth_fcs_err' in item:
                        iface_key = item['interface']
                        ifaces_new[iface_key] = item

                with open(file_cur) as file:
                    data_cur = json.load(file)
                    data_cur = data_cur['TABLE_interface']['ROW_interface']

                for item_cur in data_cur:
                    if item_cur['interface'] in ifaces_all[box] and 'eth_fcs_err' in item_cur:
                        iface_key = item_cur['interface']
                        ifaces_cur[iface_key] = item_cur

                result[box] = create_iff_errs_diff(ifaces_new, ifaces_cur)

                ifaces_new.clear()
                ifaces_cur.clear()

    return render_template('iface_core_errs.html', ifaces=result, created_new = created_new, created_cur = created_cur, conf=conf )
