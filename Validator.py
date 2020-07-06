import requests
import pickle
import json
import socketserver
import configparser
import traceback
from prometheus_client import start_http_server, Summary, Gauge, Counter
from prometheus_client.parser import text_string_to_metric_families

# Prometheus Monitoring Tools
g_prb_total = Gauge('n_prb_total', 'total number of physical resource blocks')
g_rbgs_total = Gauge('rbgs_total', 'Radio block groups for a slice') # can add labels
g_prb_available = Gauge('n_prb_open', 'number of available physical resource blocks')
g_rbgs_available = Gauge('n_rbgs_open', 'number of available resource block groups')
g_prb_util_ul = Gauge('prb_util_ul', 'progressive counter of UL PRBs scheduled so far')
g_prb_util_dl = Gauge('prb_util_dl', 'progressive counter of DL PRBs scheduled so far')
c_num_req = Counter('number_of_requests', 'Number of Control Requests')
g_dl_freq = Gauge('dl_earfcn', 'Downlink Frequency')
g_ul_freq = Gauge('ul_earfcn', 'Uplink Frequency')
# g_rbgs = Gauge('rbgs_total', 'Radio block groups for slice') # can add labels this is for slices
emp_slc_tools = {}

# Empower Protocol Constants
emp_crud_result = {"0": "UNDEFINED", "1": "UPDATE", "2": "CREATE", "3": "DELETE", "4": "RETRIEVE"}
emp_msg_type = {"0": "REQUEST", "1": "RESPONSE"}
emp_action_type = {"0": "HELLO_SERVICE", "1": "CAPABILITIES_SERVICE", "2": "UE_REPORTS_SERVICE",
                   "3": "UE_MEASUREMENTS_SERVICE", "4": "MAC_PRB_UTILIZATION", "5": "HANDOVER"}

# Empower Validator and Controller Metrics
emp_valid_met = {}
emp_ctrl_met = {}
emp_slice_met = {}

# Addresses
valid_addr = set([])
# emp_control_vbs = {"": set([])}  # keep track of enbs registered to a controller (ip)?


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
    # """Creates prometheus monitoring tools and maps them to slice."""
    # Need this to be dynamic...
    # represents slice update
    if key not in emp_slc_tools.keys():
        # ip = key[0].replace('.', '_')
        # met_name = 'rbgs_total'
        # g_rbgs = Gauge(met_name, 'Radio block groups for slice', ['IP_' + ip, 'SLICE_' + key[1]])
        met = {"rbgs": value}
        emp_slice_met = {key: met}
        # g_rbgs.set(value)
        # emp_slc_tools[key] = [g_rbgs]
    else:
        # g_rbgs.set(value)
        emp_slice_met[key]['rbgs'] = value

    print(emp_slice_met)


def update_metrics(res):
    """Updates the Slice metrics in Prometheus"""
    # Works for single cell...
    # FOR LIST: 1 - MAC VBS, 3 - pci_val, 5 - dl_earfcn val, 7 - dl_earfcn_, val 9 - n_prb val
    # res = res[0].split()
    # g_prb.set(res[9])
    # c_num_req.inc()
    # g_dl_freq.set(res[5])
    # g_ul_freq.set(res[7])

    # FOR DICT: addr, pci, dl_earfcn, ul_earfcn, n_prbs, mac_prb_utilization
    res = pickle.loads(res[0])
    g_prb_total.set(res['n_prbs'])
    g_rbgs_total.set(calculate_rbgs(res['n_prbs']))
    c_num_req.inc()
    g_dl_freq.set(res['dl_earfcn'])
    g_ul_freq.set(res['ul_earfcn'])

    # Requires PRB_UTILIZATION worker
    try:
        g_prb_util_dl.set(res['mac_prb_utilization']['dl_prb_counter'])
        g_prb_util_ul.set(res['mac_prb_utilization']['ul_prb_counter'])
        g_prb_available.set(res['mac_prb_utilization']['prb'])
        g_rbgs_available.set(calculate_rbgs(res['mac_prb_utilization']['prb']))
        # Can get physical cell id with res['mac_prb_utilization']['pci']
    except Exception as e:
        # print(traceback.format_exc())
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
    # print(msg)

    # get slice information
    slice = msg[1].decode('utf-8').split()
    # print(slice)

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


def select_policy(addr, valid_met, ctrl_met, msg_type, result_type, action_type, type='None'):
    """Selects a policy based on the passed fields."""
    # emp_crud_result {"0": "UNDEFINED", "1": "UPDATE", "2": "CREATE", "3": "DELETE", "4": "RETRIEVE"}
    # emp_msg_type {"0": "REQUEST", "1": "RESPONSE"}
    # emp_action_type {"0": "HELLO_SERVICE", "1": "CAPABILITIES_SERVICE", "2": "UE_REPORTS_SERVICE",
    #                    "3": "UE_MEASUREMENTS_SERVICE", "4": "MAC_PRB_UTILIZATION", "5": "HANDOVER"}
    if type == 'None':
        return 'YES'
    if type == 'Demo':
        return demo_policy()
    if msg_type == 'RESPONSE':
        # Allow application responses to RAN to flow through
        return 'YES'
    if result_type == "UNDEFINED":
        # Drop Packet with an undefined crud result
        return 'NO'
    else:
        # Based on action type check for expected network stats e.g thresholds and stuff?
        slices, res_info = get_slices(addr)
        pass


def get_slices(addr=None):
    """Returns slice keys (addr, slice_id) and info associated with the passed address. Returns all info no address."""
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

    def handle(self):
        """Validates the incoming control msg and relays decision back to client."""
        # Validate IP address
        if not is_valid_addr(self.client_address[0]):
            self.send_rejection('Received Packet from Unknown IP address: {}'.format(self.client_address[0]))
            return
        # if not self.validate_addr():
        #     return

        # Parse Control Message
        self.data = self.request.recv(2048).strip()
        msg_ = self.data.split(b'\n\n\n')

        # Add error handling
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

        # self.data = b''
        # for i in range(100):
        #     if b'\r\n\r\n' not in self.data:
        #         self.data += self.request.recv(4096).strip()
        #     else:
        #         break

        # try:
        #     control, resources = parse_empower_msg(self.data)
        # except:
        #     self.send_rejection('Received Malformed Control Packet.')
        #     return

        # Send Response to Client
        # self.request is the TCP socket connected to the client

    def handle_slice_creation(self, slice):
        """Handles a slice creation message."""
        #TODO: If slice and project already exist assume its an update or something...
        '''
        0 - LTE tag
        1 - slice id
        2 - slice id value
        3 - rbgs
        4 - rgbs value
        5 - ue scheduler
        6 - ue scheduler type
        '''
        slice_id = slice[2] # Maybe should use project id instead??
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
        resp = select_policy(self.client_address[0], v_metrics, c_metrics, msg_type, result_type, action_type)

        # Update Metrics
        if resp == 'YES':
            update_metrics(resources)

        return resp

    def send_rejection(self, msg):
        print(msg)
        self.request.sendall(bytes('NO', "utf-8"))
        print("Packet has been dropped.")

    # def validate_addr(self):
    #     """Validates the client address. If new address, then adds or rejects an address based on the protocol."""
    #     if not is_valid_addr(self.client_address[0]):
    #         # Check whether handshake protocol
    #         try:
    #             self.data = self.request.recv(1024).strip().decode('utf-8')
    #         except:
    #             print('Received Packet from Unknown IP address.')
    #             self.request.sendall(bytes('NO', "utf-8"))
    #             print("Packet has been dropped.")
    #             return False
    #
    #         # Respond based on protocol
    #         if self.data == "HELLO":
    #             print('Connection has been established with IP:{} Port:{}'.format(self.client_address[0],
    #                                                                               self.client_address[1]))
    #             valid_addr.add(self.client_address[0])
    #             self.request.sendall(bytes('OK', 'utf-8'))
    #             return True
    #         else:
    #             print('Received Packet from Unknown IP address.')
    #             self.request.sendall(bytes('NO', "utf-8"))
    #             print("Packet has been dropped.")
    #             return False
    #
    #     return True


if __name__ == "__main__":
    # Parse Config IP Addresses
    config = configparser.ConfigParser()
    config.read('config.ini')
    for key in config['Address']:
        valid_addr.add(config['Address'][key])

    # Start HTTP server to log info to Prometheus
    start_http_server(7999)
    print('Started Prometheus Client on port 7999.')

    # Create the server for application communication
    print("Running Validator. Listening on port 9999.")
    HOST, PORT = "localhost", 9999
    with socketserver.TCPServer((HOST, PORT), TCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()
