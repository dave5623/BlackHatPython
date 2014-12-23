import sys
import socket
import getopt
import threading
import subprocess

listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0


def client_handler(client_socket):
    global upload
    global execute
    global command

    # check if its an upload
    if len(upload_destination):
        file_buffer = ""

        # read all of the data
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            else:
                file_buffer += data

        # write out data from file_buffer
        try:
            file_descriptor = open(upload_destination, "wb")
            file_descriptor.write(file_buffer)
            file_descriptor.close()

            client_socket.send("Successfully saved file to %s\r\n" % upload_destination)
        except:
            client_socket.send("Failed to save file to %s\r\n" % upload_destination)


    # check if its a command execution
    if len(execute):
        output = run_command(execute)
        client_socket.send(output)

    if command:
        while True:
            # show a prompt
            client_socket.send("<BHP:#> ")

            # receive until we hit a return feed
            cmd_buffer = ""
            while "\n" not in cmd_buffer:
                cmd_buffer += client_socket.recv(1024)

            # send the command prompt again
            response = run_command(cmd_buffer)

            # send the response
            client_socket.send(response)


def client_sender(buffer):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((target, port))

        if len(buffer):
            client.send(buffer)

            while True:
                recv_len = 1
                response = ""

                while recv_len:
                    data = client.recv(4096)
                    recv_len = len(data)
                    response += data

                    if recv_len < 4096:
                        break

                # trailing , prevents newline from being automatically printed
                print response,

                buffer = raw_input("")
                buffer += "\n"

                client.send(buffer)

    except:
        print "[*] Exception! Exiting."
        client.close()


def server_loop():
    global target

    # listen on all interfaces if no target interface is specified
    if not len(target):
        target = "0.0.0.0"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((target, port))
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        client_thread = threading.Thread(target=client_handler, args=(client_socket,))
        client_thread.start()


def run_command(command):
    command = command.rstrip()

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command.\r\n"

    return output


def usage():
    print "BHP Net Tool"
    print
    print "Usage: netcat.py -t target_host -p port"
    print "-l --listen - listen on [host]:[port] for incoming connections"
    print "-e --execute=file_to_run - execute the given file upon receiving a connection"
    print "-c --command - initialize a command shell"
    print "-u --upload=destination - upon receiving connection upload a file and write to [destination]"
    print
    print
    print "netcat.py -t 192.168.0.1 -p 5555 -l -c"
    print "netcat.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe"
    print "netcat.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\""
    print "echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.11.12 -p 135"
    sys.exit(0)


def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target

    if not len(sys.argv[1]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hle:t:p:cu:",
                                   ["help", "listen", "execute", "target", "port", "command", "upload"])
    except getopt.GetoptError as err:
        print str(err)
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            listen = True
        elif o in ("-e", "--execute"):
            execute = True
        elif o in ("-c", "--command"):
            command = True
        elif o in ("-u", "--upload"):
            upload_destination = a
        elif o in ("-t", "--target"):
            target = a
        elif o in ("-p", "--port"):
            port = int(a)
        else:
            assert False, "Unhandled Option"

    if not listen and len(target) and port > 0:
        # read from stdin
        # blocking call
        buffer = sys.stdin.read()

        # send data
        client_sender(buffer)

    if listen:
        server_loop()


main()