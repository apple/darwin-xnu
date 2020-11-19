#!/usr/bin/python
from __future__ import absolute_import, print_function
import socket
import time
import select
import sys

_CONTROL_PORT = 17694

def waitformsgs(client_sockets, msg):
  client_sockets_set = set(client_sockets)
  while len(client_sockets_set) > 0:
    rl, _, _ = select.select(client_sockets_set, [], [])
    for client_socket in rl:
      sentmsg = client_socket.recv(1024)
      if sentmsg == msg:
        client_sockets_set.remove(client_socket)

def main(num_clients, test_type, num_threads, job_size, args):
  client_sockets = []
  control_socket = socket.socket()
  control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  control_socket.bind(("", _CONTROL_PORT))
  control_socket.listen(num_clients)
  while(len(client_sockets)<num_clients):
    client_socket, _ = control_socket.accept()
    msg = "\0".join(["%s\0%d\0%d" % (test_type, num_threads, job_size)] + args) + "\0\0"
    client_socket.send(msg)
    client_sockets.append(client_socket)

  control_socket.close()

  waitformsgs(client_sockets, "Ready")

  start_time = time.time()

  for client_socket in client_sockets:
    client_socket.shutdown(socket.SHUT_WR)

  waitformsgs(client_sockets, "Done")


  for client_socket in client_sockets:
    client_socket.close()

  end_time = time.time()
  return end_time - start_time

def usage():
  sys.stderr.write("usage: start_tests.py num_clients type threads size\n")
  exit(1)

if __name__ == "__main__":
  if len(sys.argv) < 5:
    usage()
  try:
    num_clients = int(sys.argv[1])
    test_type = sys.argv[2]
    num_threads = int(sys.argv[3])
    job_size = int(sys.argv[4])
    args = sys.argv[5:]
  except ValueError:
    usage()

  print(main(num_clients, test_type, num_threads, job_size, args))
