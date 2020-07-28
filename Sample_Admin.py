import requests
import pickle
import json
import configparser
import traceback
import socket
import pprint
from os import system

HOST = "localhost"  # Configure to point at Master Controller
PORT = 9999  # Configure to point at Master Controller
# ISMI = 998981234560301  # nexus
IMSI = 998980123456789  # srsue
pp = pprint.PrettyPrinter(indent=2)


def main():
    """Entry point into application."""
    # Open Connection with Master Controller
    print('Login successful.')

    # Start Admin Shell
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Connect to Master Controller
            try:
                sock.connect((HOST, PORT))
            except Exception:
                print('FATAL ERROR: Could not establish connection with master controller.')
                exit(1)

            # Enter Command
            cmd = input('admin@Controller:~$ ')
            cmd_ = parse_cmd(cmd.lower())

            # Parse Command
            if cmd_ is None:
                print('ERROR: Unknown command.')
            elif cmd_ == 'blank':
                print('admin@Controller:~$ ')
            elif cmd_ == 'clear':
                clear()
            elif cmd_ == 'help':
                help()
            else:
                # Determine command
                if cmd_[0] == 'exit':
                    m = 'Exiting Admin Application...'
                    # execute_cmd(cmd, sock, m) If exit need to remove admin app
                    exit(0)
                elif cmd_[0] == 'test':
                    m = 'Executing test command...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'get-all':
                    m = 'Getting all project information...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'get-workers':
                    m = 'Getting all worker information...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'get-apps':
                    m = 'Getting all application information...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'start-app':
                    m = 'Starting slice service...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'start-worker':
                    m = 'Starting instance worker...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'kill':
                    m = 'Removing project...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'kill-worker':
                    m = 'Removing worker...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'kill-app':
                    m = 'Removing application...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'get-measurements':
                    m = 'Getting measurements...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'create-project':
                    m = 'Creating Project...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'create-slice':
                    m = 'Creating Slice...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'update-slice':
                    m = 'Updating Slice...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'get-slices':
                    m = 'Getting slice information...'
                    execute_cmd(cmd, sock, m)
                else:
                    print('ERROR: Command has not been implemented.')


def parse_cmd(cmd):
    """Validates command."""
    cmd_arr = cmd.split()

    # Blank Space
    if len(cmd_arr) == 0:
        return 'blank'

    # Clear
    if cmd_arr[0] == 'clear':
        return 'clear'

    # Help
    if cmd_arr[0] == 'help':
        return 'help'

    # Valid Commands
    if cmd_arr[0] != 'exit' and cmd_arr[0] != 'test' and cmd_arr[0] != 'get-all' and \
            cmd_arr[0] != 'kill' and cmd_arr[0] != 'start-app' and cmd_arr[0] != 'get-slices' \
            and cmd_arr[0] != 'get-measurements' and cmd_arr[0] != 'create-project' \
            and cmd_arr[0] != 'create-slice' and cmd_arr[0] != 'update-slice' and cmd_arr[0] != 'start-worker' \
            and cmd_arr[0] != 'kill-app' and cmd_arr[0] != 'kill-worker' and cmd_arr[0] != 'get-apps' \
            and cmd_arr[0] != 'get-workers':
        return None

    # Argument Length Checks
    if (cmd_arr[0] == 'exit' or cmd_arr[0] == 'test' or cmd_arr[0] == 'get-all') and len(cmd_arr) > 1:
        return None
    elif (cmd_arr[0] == 'get-slices' or cmd_arr[0] == 'get-apps' or cmd_arr[0] == 'kill-worker'
          or cmd_arr[0] == 'start-worker') and len(cmd_arr) != 3:
        return None
    elif (cmd_arr[0] == 'get-workers' or cmd_arr[0] == 'create-project') and len(cmd_arr) != 2:
        return None
    elif (cmd_arr[0] == 'kill-app' or cmd_arr[0] == 'create-slice') and len(cmd_arr) != 4:
        return None
    elif cmd_arr[0] == 'get-measurements' and (len(cmd_arr) != 1 and len(cmd_arr) != 3):
        return None
    elif (cmd_arr[0] == 'update-slice') and (len(cmd_arr) < 4 or len(cmd_arr) > 6):
        return None
    elif cmd_arr[0] == 'start-app' and (len(cmd_arr) != 5 and len(cmd_arr) != 6):
        return None
    elif cmd_arr[0] == 'kill' and (len(cmd_arr) < 3 or len(cmd_arr) > 4):
        return None

    return cmd_arr


def execute_cmd(cmd, sock, m):
    """Executes a command."""
    # Send command to master controller
    send_cmd(cmd, sock, m)

    # Receive response from Master
    isObj = False
    received = sock.recv(2048)
    arr = received.split(b'\n\n\n')

    # Parse Response
    if arr[0].decode('utf-8') == 'TEXT':
        received = str(arr[1], "utf-8")
    elif arr[0].decode('utf-8') == 'OBJ':
        received = pickle.loads(arr[1])
        isObj = True
    elif arr[0].decode('utf-8') == 'NO':
        received = str(arr[0], "utf-8")
    else:
        print('Error: Received unknown response {}.'.format(arr[0].decode('utf-8')))
        return

    # Print response
    if received != 'NO':
        if isObj:
            pp.pprint(received)
        else:
            print(received, '\n')
    else:
        print('Error response received from server. Try again.', '\n')


def send_cmd(cmd, sock, m):
    """Sends a command to the master controller."""
    msg = 'ADMIN'.encode('utf-8') + b'\n\n\n' + cmd.encode('utf-8')
    print(m)
    sock.sendall(msg)


def clear():
    """Clears the terminal window."""
    _ = system('clear')


def help():
    """Prints out all the commands."""
    print('test - Sends a test command to the master controller and returns ok if successful - "test" ')
    print('get-all - Returns all the project information for all instances  - "get-all" ')
    print('get-slices - Returns all slice information in a project - "get-slices instance_id project_id"')
    print('get-apps - Returns all the applications running on a project  - "get-apps instance_id project_id"')
    print('get-workers - Returns all the workers running on an instance - "get-workers instance_id"')
    print('kill - Ends a project or removes a slice - "kill instance_id project_id [slice_id]" ')
    print('kill-app - Ends an application - "kill-app instance_id project_id app_id" ')
    print('kill-worker - Ends a worker - "kill instance_id worker_id" ')
    print('start-app - starts an application - "start-app instance_id project_id app_type [app args]"'
          '\n\t APP TYPES and ARGS: ue-measurements imsi')
    print('start-worker - starts a worker - "start-worker instance_id worker_type"\n\t WORKER TYPES: mac-prb-util ')
    print('get-measurements - Returns all UE measurements - "get-measurements [instance_id] [imsi]" ')
    print('create-project - Creates a project - "create-project instance_id" ')
    print('create-slice - Creates a slice on a project - "create-slice instance_id project_id slice_id" ')
    print('update-slice - Updates a slice on a project - "update-slice instance_id project_id slice_id [rbgs]'
          ' [ue_scheduler]''\n\t UE_SCHEDULER: 0 - Round Robin')


if __name__ == "__main__":
    main()
