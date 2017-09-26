import logging


class Message(object):
    """represents a message of Remote serial protocol"""
    def __init__(self, data):
        super(Message, self).__init__()
        self.data = data

    def __str__(self):
        return "Message: %s" % (self.data)

    def getData(self):
        #TODO need to parse data and unescape
        return self.data
    
    def getRSPByteData(self):
        retval = ''.join(['$',self.data,'#'])
        checksum = 0
        for i in self.data:
            checksum += ord(i)
        checksum = checksum % 0x100
        checksum_str = "{:02x}".format(checksum)
        retval += checksum_str
        return retval

    @classmethod
    def fromRSPByteData(cls, bytedata):
        data_begin = 0
        data_end = 0
        try:
            data_begin = bytedata.index('$')
            data_end = bytedata.index('#')
        except ValueError, e:
            logging.error('Invalid bytedata considered as message %s' % bytedata)
            return None
                
        #validate the data
        if data_begin + 1 >= data_end:
            logging.debug("empty message %s"%bytedata)
            data_begin -= 1

        data_begin += 1
        logging.debug("Creating message from data %s" % bytedata[data_begin:data_end])
        ret_obj = cls(bytedata[data_begin:data_end])
        return ret_obj

class ProtocolAcknowledgement(Message):
    """Ack Messages"""
    def __init__(self, ack_str):
        super(ProtocolAcknowledgement, self).__init__(ack_str)
        self.data = ack_str
    
    def getRSPByteData(self):
        return self.data


OKMessage = Message('OK')

AckMessage = ProtocolAcknowledgement('+')
NAckMessage = ProtocolAcknowledgement('-')
UnSupportedMessage = Message('')
