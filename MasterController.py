import requests
import pickle
import json
import socketserver
import configparser
import traceback
import threading
from prometheus_client import start_http_server, Summary, Gauge, Counter
from prometheus_client.parser import text_string_to_metric_families

# Prometheus Monitoring Tools
# Resources within an instance:
g_prb_total = Gauge('n_prb_total', 'total number of physical resource blocks for an instance', ['ip', 'mac'])
g_rbgs_total = Gauge('rbgs_total', 'total number of Radio block groups for an instance', ['ip', 'mac'])
g_dl_freq = Gauge('dl_earfcn', 'Downlink Center Frequency for an instance', ['ip', 'mac'])
g_ul_freq = Gauge('ul_earfcn', 'Uplink Center Frequency for an instance', ['ip', 'mac'])
g_slice_rbgs = Gauge('n_rbgs_alloc', 'number of allocated resource block groups for a slice', ['ip', 'projId',
                                                                                               'sliceId'])

# Resources by Instance:
g_prb_available = Gauge('n_prb_open', 'number of available physical resource blocks for an instance', ['ip'])
g_rbgs_available = Gauge('n_rbgs_open', 'number of available resource block groups for an instance', ['ip'])
g_prb_util_ul = Gauge('prb_util_ul', 'progressive counter of UL PRBs scheduled so far in an instance', ['ip'])
g_prb_util_dl = Gauge('prb_util_dl', 'progressive counter of DL PRBs scheduled so far in an instance', ['ip'])
c_num_req = Counter('number_of_requests', 'Number of Control Requests for an instance', ['ip'])

# Admin Supported Commands
valid_admin_cmd = set(['test', 'get-all', 'start-app', 'start-worker', 'kill', 'get-measurements', 'create-project',
                       'create-slice', 'update-slice', 'get-slices', 'get-apps', 'get-workers', 'kill-app',
                       'kill-worker'])

# Empower Protocol Constants
emp_crud_result = {"0": "UNDEFINED", "1": "UPDATE", "2": "CREATE", "3": "DELETE", "4": "RETRIEVE"}
emp_msg_type = {"0": "REQUEST", "1": "RESPONSE"}
emp_action_type = {"0": "HELLO_SERVICE", "1": "CAPABILITIES_SERVICE", "2": "UE_REPORTS_SERVICE",
                   "3": "UE_MEASUREMENTS_SERVICE", "4": "MAC_PRB_UTILIZATION", "5": "HANDOVER"}

# Empower Validator and Controller Metrics
emp_valid_met = {}
emp_ctrl_met = {}
emp_local_slice_met = {}
thresholds = {}
policy_type = ''

# Addresses
instance_id_to_addr = {}  # Controller instances
valid_addr = set([])  # Authorized addresses
emp_control_vbs = {}  # {"": set([])} IP to VBS macs

# TODO: Convert these to one dict e.g. IP -> Projects -> Slice IDs
emp_control_slices = {}  # {"": set([])} Projects to Slice IDs
emp_control_projects = {}  # {"": set([])} IP to Projects
# emp_addrs = set([])  # In use addresses


def parse_metrics(metrics, type):
    """Prints all the metrics via std_out."""
    for family in text_string_to_metric_families(metrics.decode('utf-8')):
        for sample in family.samples:
            add_to_dict(list(sample), type)


def add_to_dict(sample_list, type):
    """Adds sample data to respective dictionary."""
    key = sample_list[0]
    labels = sample_list[1]
    val = sample_list[2]

    if type == 'v':
        # emp_valid_met[key] = val
        emp_valid_met[key] = {"value": val, "labels": labels}
    elif type == 'c':
        # emp_ctrl_met[key] = val
        emp_ctrl_met[key] = {"value": val, "labels": labels}
    else:
        print('Error. Invalid Metric Type.')


def update_slice_stats(addr, proj_id, slc_id, value, rem=False):
    """Updates slice information both locally and via prometheus."""

    """
    LABEL NOTES:
        Group 2: This will fine grain breakdown of resources within instances
            - Multiple Slices: ip addr and slice id for individual resources (rbgs)
                - ip addr to accomodate multiple instances
                - slice id to accomodate multiple slices within an instance
        Implementation:
            - Need local structure to query whether (address, slice id)
                - emp_control_slices: IP to Slice IDs (key to set)
            - If ip exist, update backend and current prom stats with corresponding label
            - If not, update backend view, insert new labels, update metrics 
    """

    # Deletion
    if rem:
        # Update view upon slice deletion
        if slc_id is None:
            for slc in emp_control_slices[proj_id]:
                g_slice_rbgs.labels(addr, proj_id, slc).set(value)
                emp_local_slice_met.pop((addr, proj_id, slc))
        else:
            g_slice_rbgs.labels(addr, proj_id, slc_id).set(value)
            emp_local_slice_met.pop((addr, proj_id, slc_id))

        # Update local resource view upon slice deletion
        if slc_id is None:
            emp_control_projects[addr].remove(proj_id)
            emp_control_slices.pop(proj_id)
        else:
            emp_control_slices[proj_id].remove(slc_id)

    # Addition / Update
    else:
        # Update keys
        if addr not in emp_control_projects:
            emp_control_projects[addr] = set([proj_id])
        if proj_id not in emp_control_slices:
            emp_control_slices[proj_id] = set([slc_id])

        # Update local view of slices (ip -> project -> slices)
        emp_control_projects[addr].add(proj_id)
        emp_control_slices[proj_id].add(slc_id)

        # Update local view of slice resources
        if (addr, proj_id, slc_id) in emp_local_slice_met.keys():
            emp_local_slice_met[(addr, proj_id, slc_id)]['rbgs'] = value
        else:
            emp_local_slice_met[(addr, proj_id, slc_id)] = {'rbgs': value}

        # Update Prometheus
        g_slice_rbgs.labels(addr, proj_id, slc_id).set(value)


def update_metrics(ip, res):
    """Updates the physical metrics in Prometheus"""

    """ LABELS: 
            Group 1: This differentiate metrics based on instance and breakdown of resources within instances...
                - MULTIPLE eNBs: eNB MAC with ip addr for total resources (n_prb, rbgs, DL freq, UL, freq)
                    - ip addr to accomodate multiple instances
                    - eNB addr to accomodate multiple eNBs on an instance 
                        - n/a mac will represent entire instance...
                - Total Number of Requests and UTILs: differentiated with ip addr
                    - ip addr to accomodate different instances
            
        Implementation:
            - Need local structures to query whether (address, eNB mac), or address exist
                - emp_control_vbs: IP to VBS macs (key to set)
            - If ip exist, update backend view and current prom stats with corresponding label
            - If not, update backend view, insert new labels, update metrics 
    """

    # FOR DICT: addr, pci, dl_earfcn, ul_earfcn, n_prbs, mac_prb_utilization
    res = pickle.loads(res[0])
    mac = res['addr']

    # Update Local View
    if ip in emp_control_vbs.keys():
        emp_control_vbs[ip].add(mac)
    else:
        emp_control_vbs[ip] = set([mac])

    # Update Prometheus
    g_prb_total.labels(ip, mac).set(res['n_prbs'])
    g_prb_total.labels(ip, 'n/a').inc(res['n_prbs'])  # Total View of Instance
    g_rbgs_total.labels(ip, mac).set(calculate_rbgs(res['n_prbs']))
    g_rbgs_total.labels(ip, 'n/a').inc(calculate_rbgs(res['n_prbs']))  # Total View of Instance
    g_dl_freq.labels(ip, mac).set(res['dl_earfcn'])
    g_ul_freq.labels(ip, mac).set(res['ul_earfcn'])
    c_num_req.labels(ip).inc()

    # Stats that require PRB_UTILIZATION service
    try:
        g_prb_util_dl.labels(ip).set(res['mac_prb_utilization']['dl_prb_counter'])
        g_prb_util_ul.labels(ip).set(res['mac_prb_utilization']['ul_prb_counter'])
        g_prb_available.labels(ip).set(res['mac_prb_utilization']['prb'])
        g_rbgs_available.labels(ip).set(calculate_rbgs(res['mac_prb_utilization']['prb']))
        # Can get physical cell id with res['mac_prb_utilization']['pci']
    except Exception as e:
        print('No network state updates.')


def calculate_rbgs(prbs):
    """Calculates the number of resource block groups."""
    if prbs % 2 == 0:
        return prbs / 2
    else:
        return (prbs // 2) + 1


def parse_empower_ctrl_msg(msg):
    """Parses an empower control message and returns its components."""
    # get control msg
    control = pickle.loads(msg[1])

    # get resource abstractions
    res = msg[2].split(b'\n')
    return control, res


def parse_empower_slice_msg(msg):
    """Parses an empower slice creation message and returns its components."""
    # get slice information
    slice = msg[1].decode('utf-8').split()

    # get resource abstractions (proj may not have any needed infos except id?)
    proj = msg[2].decode('utf-8')
    return slice, proj


def check_msg_format(control):
    """Ensures properly formatted msg was received."""
    return is_valid_empower_msg_field(control.flags.msg_type, 'type') and is_valid_empower_msg_field(
        control.tsrc.crud_result, 'crud') and is_valid_empower_msg_field(control.tsrc.action, 'action')


def is_valid_empower_msg_field(field, id):
    """Checks whether the empower control has a valid message type"""
    if id == 'type':
        return str(field) in emp_msg_type.keys()
    elif id == 'crud':
        return str(field) in emp_crud_result.keys()
    elif id == 'action':
        return str(field) in emp_action_type.keys()
    else:
        return False


def is_valid_addr(addr):
    """Checks whether the message was received by a valid ip address."""
    return addr in valid_addr


def select_policy(addr, valid_met, ctrl_met, msg_type, result_type, action_type):
    """Selects a policy based on the passed fields."""
    if policy_type == 'None':
        return 'YES'
    elif policy_type == 'Demo':
        return demo_policy()
    else:
        # Allow application responses to RAN to flow through
        if msg_type == 'RESPONSE':
            return 'YES'
        # Drop Packet with an undefined crud result
        if result_type == "UNDEFINED":
            print('Undefined crud result received.')
            return 'NO'
        # Based on action type check for expected network stats e.g thresholds and stuff?
        return net_state_policy(addr, valid_met, ctrl_met, action_type)


def net_state_policy(addr, valid_met, ctrl_met, action_type):
    """Checks for the expected network state based on threshold values and action type."""
    """
    Config Thresholds
    min_rbgs
    max_rbgs
    tcp_in_out
    sockstat_tcp
    sockstat_mem
    tcp_direct_trans
    net_traffic
    """

    # TODO: Need to make decision based on project not entire instance i.e. other projects should still be functional
    # TODO: vary policy based on action_type?
    # TODO: Update to filter based on labels for certain metrics
    # TODO: How to query alerts correctly. How to differentiate between instances?

    slices, res_info = get_slices(addr)

    # Verify that no alerts are firing
    # https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/#inspecting-alerts-during-runtime
    # if ctrl_met['RapidControlReq'] == 1:
    #     print('Resource anomalies have been detected.')
    #     return 'NO'

    # Ensure resources are within thresholds
    for r in res_info:
        if r < thresholds['min_rbgs'] or r > thresholds['max_rbgs']:
            print('Network slices exceed resource block group threshold bounds.')
            return 'NO'

    # Ensure controller network state is within thresholds
    if invalid_net_state(ctrl_met):
        print('Network is in an invalid state and may be under attack.')
        return 'NO'

    return 'YES'


def invalid_net_state(ctrl_met):
    """Checks for valid network state. Returns true if net state is out of bounds, and false otherwise."""
    # TODO: Update to filter based on labels for certain metrics
    return ctrl_met['node_netstat_Tcp_OutSegs']['value'] / 100000 > thresholds['tcp_in_out'] \
           or ctrl_met['node_sockstat_TCP_mem_bytes']['value'] / 100000 > thresholds['sockstat_mem'] \
           or ctrl_met['node_sockstat_TCP_tw']['value'] > thresholds['sockstat_tcp'] \
           or ctrl_met['node_netstat_Tcp_PassiveOpens']['value'] / 1000 > thresholds['tcp_direct_trans'] \
           or ctrl_met['node_network_receive_bytes_total']['value'] / 10000 > thresholds['net_traffic']


def get_slices(addr=None):
    """Returns slice keys and the info associated with the passed address. Returns all info no address passed."""
    slices = []
    rbgs = []
    for key in emp_local_slice_met.keys():
        if addr is None or addr == key[0]:
            slices.append(key)
            rbgs.append(float(emp_local_slice_met[key]['rbgs']))
    return slices, rbgs


def demo_policy():
    """Caps controller requests at 20 for an entire session."""
    num_req = emp_valid_met['number_of_requests_total']['value']
    if num_req < 20:
        resp = 'YES'
    else:
        resp = 'NO'
    return resp


class TCPHandler(socketserver.BaseRequestHandler):
    """Handles Incoming TCP Connections and Messages"""

    # https://docs.python.org/2/library/socketserver.html
    # BaseRequest vs StreamRequest?? StreamRequest seems to be safer...

    def handle(self):
        """Validates the incoming control msg and relays decision back to client."""
        # Validate IP address
        if not is_valid_addr(self.client_address[0]):
            self.send_rejection('Received Packet from Unknown IP address: {}'.format(self.client_address[0]))
            return

        # Parse Control Message
        self.data = self.request.recv(2048).strip()
        msg_ = self.data.split(b'\n\n\n')

        # Handle only valid packets and respond based on protocol
        try:
            # Admin Application
            if msg_[0].decode('utf-8') == 'ADMIN':
                self.handle_admin_control(msg_)
            # Message from Slice Applications / Controller
            else:
                cmd = msg_[0].decode('utf-8')
                if cmd == 'SLICE':
                    slice, proj_id = parse_empower_slice_msg(msg_)
                    self.handle_slice_creation(slice, proj_id)
                    # emp_addrs.add(self.client_address[0])
                    print('Slice Information has been updated.')
                elif cmd == 'DEL_SLICE':
                    slice_id, proj_id = parse_empower_slice_msg(msg_)
                    self.handle_slice_deletion(slice_id[0], proj_id)
                    print('Slice Information has been updated upon deletion.')
                elif cmd == 'CONTROL':
                    control, resources = parse_empower_ctrl_msg(msg_)
                    resp = self.handle_control_msg(control, resources)
                    # emp_addrs.add(self.client_address[0])
                    if resp == 'NO':
                        print('rejected')
                        self.send_rejection('Received Malicious Control Packet.')
                    else:
                        self.request.sendall(bytes(resp, "utf-8"))
                        print("Sent Response")
                else:
                    print("Received Unknown Controller Command {}".format(cmd))
                    self.request.sendall(bytes('NO', "utf-8"))

        except Exception as e:
            print(traceback.format_exc())
            self.send_rejection('Received Malicious Control Packet.')

    def handle_slice_creation(self, slice, proj_id, admin=False, ip=None):
        """Handles a slice creation/update message."""
        # Default address
        if ip is None:
            ip = self.client_address[0]

        # Parse based on slice vs admin level application
        if admin:
            slice_id = slice[0]
            rbgs = slice[1]
        else:
            slice_id = slice[2]
            rbgs = slice[4]

        update_slice_stats(ip, proj_id, slice_id, rbgs)

    def handle_slice_deletion(self, slice_id, proj_id, ip=None):
        """Handles a slice deletion message."""
        # Default address
        if ip is None:
            ip = self.client_address[0]

        update_slice_stats(ip, proj_id, slice_id, 0, rem=True)

    def handle_control_msg(self, control, resources):
        """Handles control messages."""
        # Malformed Control Received
        if not check_msg_format(control):
            print('Malformed Packet Received.')
            return 'NO'

        try:
            # Received Valid Control
            msg_type = emp_msg_type[str(control.flags.msg_type)]
            result_type = emp_crud_result[str(control.tsrc.crud_result)]
            action_type = emp_action_type[str(control.tsrc.action)]
            print('Received Control Message: Type:{} Result:{} Action:{}'.format(msg_type, result_type, action_type))
        except Exception as e:
            print(traceback.format_exc())
            return 'NO'

        # Retrieve Metrics from Prometheus Validator and Controller
        print('Validating Message...')
        prom_addr_controller = "http://{}:9100/metrics".format(self.client_address[0])
        prom_addr_validator = "http://localhost:7999/metrics"
        # prom_addr_server = "http://localhost:9090/metrics" # maybe stores alerts

        v_metrics = requests.get(prom_addr_validator).content
        c_metrics = requests.get(prom_addr_controller).content

        # Parse Metrics
        parse_metrics(v_metrics, 'v')
        parse_metrics(c_metrics, 'c')

        # Make Decision
        resp = select_policy(self.client_address[0], emp_valid_met, emp_ctrl_met, msg_type, result_type, action_type)

        # Update Metrics
        if resp == 'YES':
            update_metrics(self.client_address[0], resources)

        return resp

    def handle_admin_control(self, msg_):
        """Handles an admin control message."""
        cmd = msg_[1].decode('utf-8').split()

        if cmd[0] not in valid_admin_cmd:
            print('Received Unknown Command from Admin application.')
            self.send_admin_response(bytes('NO', 'utf-8'))
        else:
            print('Received {} Command from Admin application.'.format(cmd[0]))
            self.execute_admin_control(cmd)

    def execute_admin_control(self, cmd):
        """Executes an admin control."""
        if cmd[0] == 'test':
            self.send_admin_response(bytes('TEXT\n\n\nok', 'utf-8'))
        elif cmd[0] == 'get-all':
            self.handle_admin_get_all()
        elif cmd[0] == 'start-app':
            if cmd[3] == 'ue-measurements':
                if len(cmd) == 6:
                    self.handle_admin_start_app(instance_id=cmd[1], proj=cmd[2], app_type=cmd[3], imsi=cmd[4],
                                                meas_id=cmd[5])
                elif len(cmd) == 5:
                    self.handle_admin_start_app(instance_id=cmd[1], proj=cmd[2], app_type=cmd[3], imsi=cmd[4])
                else:
                    raise Exception('Error incorrect number of arguments.')
            else:
                self.handle_admin_start_app(instance_id=cmd[1], proj=cmd[2], app_type=cmd[3])
        elif cmd[0] == 'start-worker':
            self.handle_admin_start_worker(instance_id=cmd[1], worker_type=cmd[2])
        elif cmd[0] == 'get-apps':
            self.handle_admin_get_apps(instance_id=cmd[1], proj_id=cmd[2])
        elif cmd[0] == 'get-workers':
            self.handle_admin_get_workers(instance_id=cmd[1])
        elif cmd[0] == 'kill':
            if len(cmd) == 4:
                self.handle_admin_kill(instance_id=cmd[1], proj=cmd[2], slice_id=cmd[3])
            elif len(cmd) == 3:
                self.handle_admin_kill(instance_id=cmd[1], proj=cmd[2])
            else:
                raise Exception('Error incorrect number of arguments.')
        elif cmd[0] == 'kill-app':
            self.handle_admin_kill_app(instance_id=cmd[1], proj=cmd[2], app_id=cmd[3])
        elif cmd[0] == 'kill-worker':
            self.handle_admin_kill_worker(instance_id=cmd[1], worker_id=cmd[2])
        elif cmd[0] == 'get-measurements':
            if len(cmd) == 3:
                self.handle_admin_measurements(instance_id=cmd[1], imsi=cmd[2])
            elif len(cmd) == 1:
                self.handle_admin_measurements()
            else:
                raise Exception('Error.')
        elif cmd[0] == 'create-project':
            self.handle_admin_create_proj(instance_id=cmd[1])
        elif cmd[0] == 'create-slice':
            if len(cmd) == 4:
                self.handle_admin_create_slice(instance_id=cmd[1], proj=cmd[2], slice_id=cmd[3])
            else:
                raise Exception('Error incorrect number of arguments.')
        elif cmd[0] == 'update-slice':
            if len(cmd) == 6:
                self.handle_admin_update_slice(instance_id=cmd[1], proj=cmd[2], slice_id=cmd[3], rgbs=cmd[4],
                                               ue_scheduler=cmd[5])
            elif len(cmd) == 5:
                self.handle_admin_update_slice(instance_id=cmd[1], proj=cmd[2], slice_id=cmd[3], rgbs=cmd[4])
            elif len(cmd) == 4:
                self.handle_admin_update_slice(instance_id=cmd[1], proj=cmd[2], slice_id=cmd[3])
            else:
                raise Exception('Error incorrect number of arguments.')
        elif cmd[0] == 'get-slices':
            if len(cmd) == 3:
                self.handle_admin_get_slices(instance_id=cmd[1], proj_id=cmd[2])
            else:
                raise Exception('Error incorrect number of arguments.')
        else:
            raise Exception('Error. Unknown command.')

    def handle_admin_get_all(self):
        """Handles an admin get-all request."""
        r = None
        data = {}

        # Loop through all instances
        for instance in instance_id_to_addr.values():
            r = requests.get('http://{}:8888/api/v1/projects/'.format(instance))
            data[instance] = json.loads(r.text)

        # Send Response
        resp = pickle.dumps(data)
        resp = 'OBJ\n\n\n'.encode('utf-8') + resp
        self.send_admin_response(resp, r)

    def handle_admin_get_apps(self, instance_id, proj_id):
        """Handles an admin get-all request."""
        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/projects/{}/apps'.format(instance, proj_id)

        # Request all running apps
        r = requests.get(url)
        resp = pickle.dumps(json.loads(r.text))
        resp = 'OBJ\n\n\n'.encode('utf-8') + resp
        self.send_admin_response(resp, r)

    def handle_admin_get_workers(self, instance_id):
        """Handles an admin get-all request."""
        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/workers/'.format(instance)

        # Request all running workers
        r = requests.get(url)
        resp = pickle.dumps(json.loads(r.text))
        resp = 'OBJ\n\n\n'.encode('utf-8') + resp
        self.send_admin_response(resp, r)

    def handle_admin_start_app(self, instance_id, proj, app_type, imsi=None, meas_id=1):
        """Handles an admin start-app request."""
        if app_type == 'ue-measurements':
            data = {"version": "1.0",
                    "name": 'empower.apps.uemeasurements.uemeasurements',
                    "params": {
                        "amount": "INFINITY",
                        "imsi": str(imsi),
                        "meas_id": str(meas_id),
                        "interval": "MS480"
                    }}
        else:
            # TODO: Support more app_types
            data = {}

        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/projects/{}/apps'.format(instance, proj)

        # Start slice application
        data = json.dumps(data)
        r = requests.post(url, data=data, auth=('root', 'root'))
        resp = 'TEXT\n\n\nstarted slice application'.encode('utf-8')
        self.send_admin_response(resp, r)

    def handle_admin_start_worker(self, instance_id, worker_type, every=2000):
        """Handles an admin start-worker request."""
        # Create data for worker
        if worker_type == 'mac-prb-util':
            data = {"version": "1.0",
                    "name": 'empower.workers.macprbutilization.macprbutilization',
                    "params": {
                        "every": every,
                    }}
        else:
            # TODO: Support more worker_types
            data = {}

        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/workers'.format(instance)

        # Start the worker
        data = json.dumps(data)
        r = requests.post(url, data=data, auth=('root', 'root'))
        resp = 'TEXT\n\n\nstarted instance worker'.encode('utf-8')
        self.send_admin_response(resp, r)

    def handle_admin_kill(self, instance_id, proj, slice_id=None):
        """Handles an admin kill project/slice request."""
        # Empower prohibits the deletion of slice 0
        if slice_id == '0':
            self.send_admin_response(msg='NO'.encode('utf-8'))
            return

        # Filter by instance
        instance = instance_id_to_addr[instance_id]

        # Format request
        if slice_id is not None:
            url = 'http://{}:8888/api/v1/projects/{}/lte_slices/{}'.format(instance, proj, slice_id)
            resp = 'TEXT\n\n\nSlice has been terminated'.encode('utf-8')
        else:
            url = 'http://{}:8888/api/v1/projects/{}'.format(instance, proj)
            resp = 'TEXT\n\n\nProject has been terminated'.encode('utf-8')

        # Delete slice or instance
        r = requests.delete(url, auth=('root', 'root'))
        self.send_admin_response(resp, r)

        # Update local view if entire project is deleted
        if 200 <= r.status_code <= 204 and slice_id is None:
            self.handle_slice_deletion(slice_id=slice_id, proj_id=proj, ip=instance)

    def handle_admin_kill_app(self, instance_id, proj, app_id):
        """Handles an admin kill-app request."""
        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/projects/{}/apps/{}'.format(instance, proj, app_id)

        # Delete an application
        resp = 'TEXT\n\n\nApplication has been terminated'.encode('utf-8')
        r = requests.delete(url, auth=('root', 'root'))
        self.send_admin_response(resp, r)

    def handle_admin_kill_worker(self, instance_id, worker_id):
        """Handles an admin kill-worker request."""
        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/workers/{}'.format(instance, worker_id)

        # Delete a worker
        resp = 'TEXT\n\n\nWorker has been terminated'.encode('utf-8')
        r = requests.delete(url, auth=('root', 'root'))
        self.send_admin_response(resp, r)

    def handle_admin_measurements(self, instance_id=0, imsi=None):
        """Handles an admin get-measurements request."""
        # Retrieve all UE measurements
        if imsi is None:
            r = None
            data = {}
            for instance in instance_id_to_addr.values():
                url = 'http://{}:8888/api/v1/users'.format(instance)
                r = requests.get(url)
                data[instance] = json.loads(r.text)
            resp = 'OBJ\n\n\n'.encode('utf-8') + pickle.dumps(data)

        # Retrieve a specific UE measurement
        else:
            # TODO: Expand to accept specific IMSI (need to get working in empower)
            instance = instance_id_to_addr[instance_id]
            url = 'http://{}:8888/api/v1/users/{}'.format(instance, imsi)
            r = requests.get(url)
            resp = 'OBJ\n\n\n'.encode('utf-8') + pickle.dumps(json.loads(r.text))

        self.send_admin_response(resp, r)

    def handle_admin_create_proj(self, instance_id):
        """Handles an admin create-project request."""
        data = {"version": "1.0",
                "desc": "test",
                "owner": "foo",
                "wifi_props": {},
                "lte_props": {
                    "plmnid": "99898"
                }
                }

        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/projects/'.format(instance)

        # Create a project
        data = json.dumps(data)
        r = requests.post(url, data=data, auth=('root', 'root'))
        resp = 'TEXT\n\n\nProject has been created.'.encode('utf-8')
        self.send_admin_response(resp, r)

    def handle_admin_create_slice(self, instance_id, proj, slice_id=1, rbgs="5", ue_scheduler=0, devices={}):
        """Handles an admin create-slice request."""
        # TODO: Need to accept devices as argument
        # TODO: Need to accept properties as arguments
        data = {"version": "1.0",
                "slice_id": str(slice_id),
                "properties": {
                    "rbgs": rbgs,
                    "ue_scheduler": ue_scheduler
                },
                "devices": devices
                }

        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/projects/{}/lte_slices/'.format(instance, proj)

        # Create a slice
        data = json.dumps(data)
        r = requests.post(url, data=data, auth=('root', 'root'))
        resp = 'TEXT\n\n\nSlice has been created.'.encode('utf-8')
        self.send_admin_response(resp, r)

    def handle_admin_update_slice(self, instance_id, proj, slice_id, rgbs=5, ue_scheduler=0, devices={}):
        """Handles an admin update-slice request."""
        # Only allow updates to existing slices
        if proj not in emp_control_slices.keys() or slice_id not in emp_control_slices[proj]:
            self.send_admin_response(msg='NO'.encode('utf-8'))
            return

        # TODO: Need to accept devices as argument
        data = {"version": "1.0",
                "slice_id": slice_id,
                "properties": {
                    "rbgs": rgbs,
                    "ue_scheduler": ue_scheduler
                },
                "devices": devices
                }

        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/projects/{}/lte_slices/{}'.format(instance, proj, slice_id)

        # Update slice information
        data = json.dumps(data)
        r = requests.put(url, data=data, auth=('root', 'root'))
        resp = 'TEXT\n\n\nSlice has been updated.'.encode('utf-8')
        self.send_admin_response(resp, r)

    def handle_admin_get_slices(self, instance_id, proj_id):
        """Handles an admin get-slices request."""
        # Filter by instance
        instance = instance_id_to_addr[instance_id]
        url = 'http://{}:8888/api/v1/projects/{}/lte_slices'.format(instance, proj_id)

        # Request slice information
        r = requests.get(url)
        resp = pickle.dumps(json.loads(r.text))
        resp = 'OBJ\n\n\n'.encode('utf-8') + resp
        self.send_admin_response(resp, r)

    def send_admin_response(self, msg, r=None):
        # Received an error
        if r is not None and (r.status_code < 200 or r.status_code > 204):
            print('ISSUE:', r.text)
            self.request.sendall(bytes('NO', 'utf-8'))

        # Send response
        self.request.sendall(msg)
        print('Sent response.')

    def send_rejection(self, msg):
        """Sends a rejection to the controller and prints the msg via stdout."""
        print(msg)
        self.request.sendall(bytes('NO', "utf-8"))
        print("Packet has been dropped.")


if __name__ == "__main__":
    # Parse IP Addresses Config
    config = configparser.ConfigParser()
    config.read('config.ini')
    for key in config['Address']:
        valid_addr.add(config['Address'][key])

    # Parse Resource Thresholds Config
    for key in config['Threshold']:
        thresholds[key] = float(config['Threshold'][key])

    # Parse Policy Type
    policy_type = config['Policy']['type']

    # Parse Instance Addresses
    for key in config['InstanceID']:
        instance_id_to_addr[key] = config['InstanceID'][key]

    # Start HTTP server to log info to Prometheus
    start_http_server(7999)
    print('Started Prometheus Client on port 7999.')

    # Create the server for application communication
    print("Running Validator. Listening on port 9999.")
    HOST, PORT = "", 9999
    with socketserver.ThreadingTCPServer((HOST, PORT), TCPHandler) as server:
        # interrupt the program with Ctrl-C
        server.serve_forever()
