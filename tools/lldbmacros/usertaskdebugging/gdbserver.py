import logging
from interface import Interface
import rsprotocol
import random


class GDBServer(object):
    """instance of gdbserver"""
    def __init__(self, backing_instance):
        super(GDBServer, self).__init__()
        self.process = backing_instance
        self.portnum = random.randint(2000, 8000)
        logging.info("Starting gdb server for localhost:%d" % self.portnum)
        self.conn = Interface('localhost', self.portnum)
        self.version_string = 'name:kdbserver;version:0.1'

    def run(self):
        if not self.conn.connect():
            logging.critical("No client connected. Bailing.")
            return False

        logging.debug('Starting gdb server.')

        while True:
            #loop for running the server.
            #read command
            readBytes = ""

            while True:
                try:
                    p_bytes = self.conn.read()
                except Exception, e:
                    logging.warn("found exception in read %s" % (str(e)))
                    logging.debug("currentbytes: %s" % readBytes)
                    readBytes = ''
                    break
                readBytes += p_bytes
                p_begin = readBytes.find('$')
                p_end = readBytes.find('#')
                if p_begin >= 0 and p_end >= 0 and p_end > p_begin:
                    break
            # ignore if empty or ack messages
            if readBytes in ('', '+'):
                logging.debug('ignoring message: %s' % readBytes)
                continue
            req_msg = rsprotocol.Message.fromRSPByteData(readBytes)
            resp = self.handleMessage(req_msg)
            #in case resp is to detach
            if resp is None:
                return True
            for r_msg in resp:
                logging.debug("response: %s" % r_msg.getRSPByteData())
                self.conn.write(r_msg.getRSPByteData())
        return True

    def handleMessage(self, msg):
        """ return array of messages that needs to responded. """
        query = msg.getData()
        replymsgs = []
        sendAck = None
        logging.debug('RCV:' + query)

        if query == "?":
            h_msg = rsprotocol.Message(self.process.getSignalInfo())
            replymsgs.append(h_msg)

        elif query[0] == 'm':
            replymsgs.append(self.getMemory(query))

        elif query in ('qVAttachOrWaitSupported'):
            logging.debug('Ignoring query %s' % query)
            replymsgs.append(rsprotocol.UnSupportedMessage)

        elif query == "qC":
            replymsgs.append(self.getCurrentThreadID(query))

        elif query[0] in ('z', 'Z'):
            logging.debug('Ignoring breakpoint query %s' % query)
            replymsgs.append(rsprotocol.UnSupportedMessage)

        elif query[0] in ('g', 'p'):
            replymsgs.append(self.getRegisterData(query))

        elif query[0] in ('P', 'G'):
            # we do not support writing into registers
            replymsgs.append(rsprotocol.Message('E05'))

        elif query in ('QStartNoAckMode'):
            replymsgs.append(rsprotocol.OKMessage)
            sendAck = True

        elif query in ('QListThreadsInStopReply', 'QThreadSuffixSupported'):
            replymsgs.append(rsprotocol.OKMessage)

        elif query == 'qGDBServerVersion':
            replymsgs.append(rsprotocol.Message(self.version_string))

        elif query == 'qShlibInfoAddr':
            #return shared library info address if any
            replymsgs.append(self.getSharedLibInfoAddress(query))

        elif query == 'qProcessInfo':
            replymsgs.append(self.getProcessInfo(query))

        elif query == 'qHostInfo':
            h_msg = rsprotocol.Message(self.process.getHostInfo())
            replymsgs.append(h_msg)

        elif query == 'vCont?':
            replymsgs.append(rsprotocol.Message('vCont;'))

        elif query == 'D':
            logging.info('Client requested to detach.')
            return None

        elif query.find('qRegisterInfo') >= 0:
            replymsgs.append(self.getRegisterInfo(query))

        elif query.find('qMemoryRegionInfo') >= 0:
            replymsgs.append(self.getMemoryRegionInfo(query))

        elif query.find('qThreadStopInfo') >= 0 or query in ('qfThreadInfo', 'qsThreadInfo'):
            replymsgs.append(self.getThreadRegistersInfo(query))

        else:
            replymsgs.append(rsprotocol.UnSupportedMessage)

        if sendAck is not None:
            if sendAck:
                replymsgs.insert(0, rsprotocol.AckMessage)
            else:
                replymsgs.insert(0, rsprotocol.NAckMessage)

        return replymsgs

    def getThreadRegistersInfo(self, query):
        bytes = ''
        if query == 'qfThreadInfo':
            bytes = self.process.getFirstThreadInfo()
        elif query == 'qsThreadInfo':
            bytes = self.process.getSubsequestThreadInfo()
        else:
            try:
                query = query.replace('qThreadStopInfo', '')
                tid = int(query, 16)
                bytes = self.process.getThreadStopInfo(tid)
            except Exception, e:
                logging.error("Failed to get register information query: %s error: %s" % (query, e.message))
        return rsprotocol.Message(bytes)

    def getRegisterData(self, query):
        if query[0] == 'g':
            #TODO should implement this sometime. Considering getThreadRegistersInfo is there
            #we wont need this one.
            return rsprotocol.UnSupportedMessage

        #the query is of type p<regnum>;thread:<id>;
        bytes = ''
        try:
            args = query[1:].split(';')
            if len(args) > 0:
                regnum = int(args[0], 16)
                if args[1].find('thread') >= 0:
                    threadid = int(args[1].split(':')[-1], 16)
                    bytes = self.process.getRegisterDataForThread(threadid, regnum)
                    logging.debug('REGISTER INFO bytes = ' + bytes)
        except Exception, e:
            logging.error("Failed to get register information query: %s error: %s" % (query, e.message))
        return rsprotocol.Message(bytes)

    def getRegisterInfo(self, query):
        bytes = ''
        try:
            query_index = query.replace('qRegisterInfo', '')
            regnum = int(query_index, 16)
            bytes = self.process.getRegisterInfo(regnum)
        except Exception, e:
            logging.error("Non-fatal: Failed to get register information: query: %s error: %s" % (query, e.message))
        return rsprotocol.Message(bytes)

    def getMemory(self, query):
        query = query[1:]
        addr, size = query.split(',')
        mem_address = int(addr, 16)
        mem_size = int(size, 16)
        bytes = ''
        try:
            bytes = self.process.readMemory(mem_address, mem_size)
        except Exception, e:
            logging.warn('Failed to read data %s' % str(e))
            return rsprotocol.Message('E03')
        return rsprotocol.Message(bytes)

    def getMemoryRegionInfo(self, query):
        return rsprotocol.UnSupportedMessage

    def setMemory(self, query):
        logging.info('Not supporting writing to memory. %s' % query)
        return rsprotocol.Message('E09')

    def getProcessInfo(self, query):
        data = ''
        try:
            data = self.process.getProcessInfo()
        except Exception, e:
            logging.error("Failed to get process information")
        return rsprotocol.Message(data)

    def getSharedLibInfoAddress(self, query):
        data = 'E44'
        try:
            data = self.process.getSharedLibInfoAddress()
            data = self.process.encodeThreadID(data)
        except Exception, e:
            logging.error("Failed to get Shared Library information")
        return rsprotocol.Message(data)

    def getCurrentThreadID(self, query):
        tid = '0'
        try:
            tid = '%x' % (self.process.getCurrentThreadID())
        except Exception, e:
            logging.error("Failed to get QC info")

        return rsprotocol.Message('QC'+tid)

    def kill(self):
        pass
