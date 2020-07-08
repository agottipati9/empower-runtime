import requests
import pickle
import json
import socketserver
import configparser
import traceback
import threading
from prometheus_client import start_http_server, Summary, Gauge, Counter
from prometheus_client.parser import text_string_to_metric_families

""" LABELS: 
    Implementation:
        - If exist, update current prom stats with corresponding label
        - If not, update backend view, insert new labels, update metrics 
        - Utilize two separate update methods (group 1 and group 2) or use flags to differentiate
"""

# Prometheus Monitoring Tools
# Resources within an instance:
g_prb_total = Gauge('n_prb_total', 'total number of physical resource blocks for an instance', ['ip', 'mac'])
g_rbgs_total = Gauge('rbgs_total', 'total number of Radio block groups for an instance', ['ip', 'mac'])
g_slice_rbgs = Gauge('n_rbgs_alloc', 'number of allocated resource block groups for a slice', ['ip', 'sliceId'])

# Resources by Instance:
g_prb_available = Gauge('n_prb_open', 'number of available physical resource blocks for an instance', ['ip'])
g_rbgs_available = Gauge('n_rbgs_open', 'number of available resource block groups for an instance', ['ip'])
g_prb_util_ul = Gauge('prb_util_ul', 'progressive counter of UL PRBs scheduled so far in an instance', ['ip'])
g_prb_util_dl = Gauge('prb_util_dl', 'progressive counter of DL PRBs scheduled so far in an instance', ['ip'])
c_num_req = Counter('number_of_requests', 'Number of Control Requests for an instance', ['ip'])
g_dl_freq = Gauge('dl_earfcn', 'Downlink Frequency for an instance', ['ip'])
g_ul_freq = Gauge('ul_earfcn', 'Uplink Frequency for an instance', ['ip'])

# Empower Protocol Constants
emp_crud_result = {"0": "UNDEFINED", "1": "UPDATE", "2": "CREATE", "3": "DELETE", "4": "RETRIEVE"}
emp_msg_type = {"0": "REQUEST", "1": "RESPONSE"}
emp_action_type = {"0": "HELLO_SERVICE", "1": "CAPABILITIES_SERVICE", "2": "UE_REPORTS_SERVICE",
                   "3": "UE_MEASUREMENTS_SERVICE", "4": "MAC_PRB_UTILIZATION", "5": "HANDOVER"}

# Empower Validator and Controller Metrics
emp_valid_met = {}
emp_ctrl_met = {}
emp_slice_met = {}
thresholds = {}
policy_type = ''

# Addresses
valid_addr = set([])  # Authorized addresses
emp_control_vbs = {}  # {"": set([])} IP to VBS macs
emp_control_slices = {}  # {"": set([])} IP to Slice IDs
emp_control_addrs = set([])  # IPs in use


def parse_metrics(metrics, type):
    """Prints all the metrics via std_out."""
    for family in text_string_to_metric_families(metrics.decode('utf-8')):
        for sample in family.samples:
            add_to_dict(list(sample), type)


def add_to_dict(sample_list, type):
    """Adds sample data to respective dictionary."""
    key = sample_list[0]
    # labels = sample_list[1]
    val = sample_list[2]

    if type == 'v':
        emp_valid_met[key] = val
    elif type == 'c':
        emp_ctrl_met[key] = val
    else:
        print('Error. Invalid Metric Type.')


def update_slice_stats(key, value):
    """Updates slice information."""
    # TODO: Need updates to be dynamic and pushed to Prometheus. Prom labels?
    if key not in emp_slice_met.keys():
        met = {"rbgs": value}
        emp_slice_met = {key: met}
    else:
        emp_slice_met[key]['rbgs'] = value


def update_metrics(res):
    """Updates the Slice metrics in Prometheus"""
    # TODO: Generalize metrics for multiple slices and eNBs...
    """ LABELS: 
            Group 1: This differentiate metrics based on instance and breakdown of resources within instances...
                - MULTIPLE eNBs: eNB MAC with ip addr for total resources (n_prb, rbgs)
                    - ip addr to accomodate multiple instances
                    - eNB addr to accomodate multiple eNBs on an instance 
                        - n/a mac will represent entire instance...
                - Total Number of Requests, DL Freq, UL Freq, and UTILs: differentiated with ip addr
                    - ip addr to accomodate different instances
            
            Group 2: This will fine grain breakdown of resources within instances
            - Multiple Slices: ip addr and slice id for individual resources (rbgs)
                - ip addr to accomodate multiple instances
                - slice id to accomodate multiple slices within an instance
                
        Implementation:
            - Need local structures to query whether (address, slice id), (address, eNB mac), or address exist
                - emp_control_vbs: IP to VBS macs (key to set)
                - emp_control_slices: IP to Slice IDs (key to set)
                - emp_control_addrs: IPs in use (set)
            - If exist, update current prom stats with corresponding label
            - If not, update backend view, insert new labels, update metrics 
            - Utilize two separate update methods (group 1 and group 2) or use flags to differentiate
    """

    # FOR DICT: addr, pci, dl_earfcn, ul_earfcn, n_prbs, mac_prb_utilization
    res = pickle.loads(res[0])
    g_prb_total.set(res['n_prbs'])
    g_rbgs_total.set(calculate_rbgs(res['n_prbs']))
    c_num_req.inc()
    g_dl_freq.set(res['dl_earfcn'])
    g_ul_freq.set(res['ul_earfcn'])

    # Requires PRB_UTILIZATION service
    try:
        g_prb_util_dl.set(res['mac_prb_utilization']['dl_prb_counter'])
        g_prb_util_ul.set(res['mac_prb_utilization']['ul_prb_counter'])
        g_prb_available.set(res['mac_prb_utilization']['prb'])
        g_rbgs_available.set(calculate_rbgs(res['mac_prb_utilization']['prb']))
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
    # proj = msg[1].decode('utf-8')
    # print(proj)
    # return slice, proj
    return slice


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


def net_state_policy(addr, action_type, valid_met, ctrl_met):
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

    # TODO: vary policy based on action_type?

    slices, res_info = get_slices(addr)
    print('Validator Metrics:', valid_met)
    print('Controller Metrics: ', ctrl_met)

    # Verify that no alerts are firing
    # https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/#inspecting-alerts-during-runtime
    # if ctrl_met['alertname'] == 1:
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
    return ctrl_met['tcp_in_out'] > thresholds['tcp_in_out'] or ctrl_met['sockstat_mem'] > thresholds['sockstat_mem'] \
           or ctrl_met['sockstat_tcp'] > thresholds['sockstat_tcp'] or ctrl_met['tcp_direct_trans'] > \
           thresholds['tcp_direct_trans'] or ctrl_met['net_traffic'] > thresholds['net_traffic']


def get_slices(addr=None):
    """Returns slice keys and the info associated with the passed address. Returns all info no address passed."""
    slices = []
    rbgs = []
    for key in emp_slice_met.keys():
        if addr is None or addr == key[0]:
            slices.append(key)
            rbgs.append(emp_slice_met[key]['rbgs'])
    return slices, rbgs


def demo_policy():
    """Caps controller requests at 20 for an entire session."""
    num_req = emp_valid_met['number_of_requests_total']
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
            if msg_[0].decode('utf-8') == 'SLICE':
                slice = parse_empower_slice_msg(msg_)
                self.handle_slice_creation(slice)
                print('Slice Information has been updated.')
            elif msg_[0].decode('utf-8') == 'CONTROL':
                control, resources = parse_empower_ctrl_msg(msg_)
                resp = self.handle_control_msg(control, resources)
                if resp == 'NO':
                    print('rejected')
                    self.send_rejection('Received Malicious Control Packet.')
                else:
                    self.request.sendall(bytes(resp, "utf-8"))
                    print("Sent Response")
        except Exception as e:
            print(traceback.format_exc())
            self.send_rejection('Received Malicious Control Packet.')

    def handle_slice_creation(self, slice):
        """Handles a slice creation message."""
        slice_id = slice[2]  # Maybe should use project id instead??
        rgbs = slice[4]
        key = (self.client_address[0], slice_id)
        update_slice_stats(key, rgbs)

    def handle_control_msg(self, control, resources):
        """Handles control messages."""
        # Malformed Control Received
        if not check_msg_format(control):
            print('bad format')
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
        v_metrics = requests.get(prom_addr_validator).content
        c_metrics = requests.get(prom_addr_controller).content

        # Parse Metrics
        parse_metrics(v_metrics, 'v')
        parse_metrics(c_metrics, 'c')

        # Make Decision
        resp = select_policy(self.client_address[0], emp_valid_met, emp_ctrl_met, msg_type, result_type, action_type)

        # Update Metrics
        if resp == 'YES':
            update_metrics(resources)

        return resp

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

    # Start HTTP server to log info to Prometheus
    start_http_server(7999)
    print('Started Prometheus Client on port 7999.')

    # Create the server for application communication
    print("Running Validator. Listening on port 9999.")
    HOST, PORT = "localhost", 9999
    with socketserver.ThreadingTCPServer((HOST, PORT), TCPHandler) as server:
        # interrupt the program with Ctrl-C
        server.serve_forever()
