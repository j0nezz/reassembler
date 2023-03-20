from enum import Enum


class FileType(Enum):
    """
    PCAP or FLOW traffic capture file options
    """
    FLOW = 'Flow'
    PCAP = 'PCAP'

    def __str__(self):
        return self.value