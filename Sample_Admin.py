import requests
import pickle
import json
import configparser
import traceback
import socket
import pprint

HOST = "localhost"
PORT = 9999
ISMI = 998981234560301
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
                    m = 'Getting all slice information...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'start':
                    m = 'Getting all slice information...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'kill':
                    m = 'Removing project...'
                    execute_cmd(cmd, sock, m)
                elif cmd_[0] == 'get-measurements':
                    m = 'Getting measurements...'
                    execute_cmd(cmd, sock, m)
                else:
                    print('ERROR: Unknown command.')


def parse_cmd(cmd):
    """Validates command."""
    cmd_arr = cmd.split()

    # Blank Space
    if len(cmd_arr) == 0:
        return 'blank'

    # Valid Commands
    if cmd_arr[0] != 'exit' and cmd_arr[0] != 'test' and cmd_arr[0] != 'get-all' and \
            cmd_arr[0] != 'kill' and cmd_arr[0] != 'start' and cmd_arr[0] != 'get-slices'\
            and cmd_arr[0] != 'get-measurements':
        return None

    # Argument Checks
    if (cmd_arr[0] == 'exit' or cmd_arr[0] == 'test' or cmd_arr[0] == 'get-all' or cmd_arr[0 == 'get-measurements']) \
            and len(cmd_arr) > 1:
        return None
    elif (cmd_arr[0] == 'kill' or cmd_arr[0] == 'get-slices') and len(cmd_arr) != 2:
        return None
    elif cmd_arr[0] == 'start' and len(cmd_arr) != 3:
        return None

    return cmd_arr


def execute_cmd(cmd, sock, m):
    """Executes a command."""
    # Send command to master controller
    send_cmd(cmd, sock, m)
    received = sock.recv(2048)

    data = pickle.loads(received)
    pp.pprint(data)

    # Receive response from Master
    # try:
    #     received = str(sock.recv(1024), "utf-8")
    # except:
    #     received = pickle.loads(received)

    if received != 'NO':
        pass
        # print(received, '\n')
    else:
        print('Error received from server. Try again.', '\n')


def send_cmd(cmd, sock, m):
    """Sends a command to the master controller."""
    msg = 'ADMIN'.encode('utf-8') + b'\n\n\n' + cmd.encode('utf-8')
    print(m)
    sock.sendall(msg)


if __name__ == "__main__":
    main()

