class paillier_send:
    def __init__(self):
        self.pkey       = None
        self.u          = None
        self.s          = None
        self.usquare    = None
 
class elgamal_send:
    def __init__(self):
        self.g = None
        self.p = None

class EntryStorage():
    def __init__(self):
        self.ID             = None
        self.noEncID        = None
        self.value          = None
        self.encValue       = None
        self.encValueInvert = None
        self.ZeroEncoding   = None
        self.OneEncoding    = None
        self.party          = None
        self.sum            = None
        self.equalityCheck  = None
        self.newID          = None
    
    def __lt__(self, other):
        """Less than comparison based on value (noEncValue)"""
        if self.value is None or other.value is None:
            return False
        return self.value < other.value
    
    def __le__(self, other):
        """Less than or equal comparison based on value (noEncValue)"""
        if self.value is None or other.value is None:
            return False
        return self.value <= other.value
    
    def __gt__(self, other):
        """Greater than comparison based on value (noEncValue)"""
        if self.value is None or other.value is None:
            return False
        return self.value > other.value
    
    def __ge__(self, other):
        """Greater than or equal comparison based on value (noEncValue)"""
        if self.value is None or other.value is None:
            return False
        return self.value >= other.value
    
    def __eq__(self, other):
        """Equal comparison based on value (noEncValue)"""
        if self.value is None or other.value is None:
            return False
        return self.value == other.value
    
    def __ne__(self, other):
        """Not equal comparison based on value (noEncValue)"""
        if self.value is None or other.value is None:
            return True
        return self.value != other.value