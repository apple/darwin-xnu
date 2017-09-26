import logging
import socket
import select

class Interface(object):
    """Basic communication interface."""
    def __init__(self, host_cfg, portnum):
        super(Interface, self).__init__()
        self.host_cfg = host_cfg
        self.portnum = portnum
        self.pkt_size = 8192
        self.socket = None
        self.isblocking = True
        logging.debug("created  %s" % str(self))

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host_cfg, self.portnum))
        logging.debug("Initializing network interface for communication host: %s:%d", self.host_cfg, self.portnum)
        self.socket.listen(5)
        num_retries = 3
        while num_retries > 0:
            ra,wa,ea = select.select([self.socket], [], [], 30)
            if not ra:
                num_retries -= 1
                logging.error("select returned empty list")
                continue
            self.connection, addr = self.socket.accept()
            logging.info("Connected to client from %s" % str(addr))
            return True
        logging.error("Failed to connect. Exiting after multiple attempts.")
        return False
    
    def read(self):
        if self.isblocking:
            #BUG TODO make this unblocking soon
            #logging.warn("blocking read bug")
            self.connection.settimeout(15)
            self.isblocking = False
        r_bytes = ''
        try:
            r_bytes = self.connection.recv(self.pkt_size)
        except Exception, e:
            #logging.debug("Found exception in recv. %s " % (str(e)))
            pass

        return r_bytes
    
    def write(self, bytes):
        if not self.isblocking:
            self.connection.setblocking(1)
            self.isblocking = True
        return self.connection.send(bytes)

    def close(self):
        if self.connection:
            logging.debug('closing connection.')
            self.connection.close()
        return self.socket

    def __str__(self):
        return "interface: %s %d" % (self.host_cfg, self.portnum)
