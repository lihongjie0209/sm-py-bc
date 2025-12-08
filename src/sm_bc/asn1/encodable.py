"""
ASN.1 Encodable protocol - base interface for all ASN.1 objects.
"""

from typing import Protocol


class ASN1Encodable(Protocol):
    """
    Protocol for objects that can be encoded to ASN.1 DER format.
    
    All ASN.1 objects implement this protocol, allowing them to be
    encoded to bytes in Distinguished Encoding Rules (DER) format.
    """
    
    def to_der(self) -> bytes:
        """
        Encode this object to DER (Distinguished Encoding Rules) format.
        
        Returns:
            bytes: The DER-encoded representation of this object
            
        Example:
            >>> obj = ASN1Integer(42)
            >>> der_bytes = obj.to_der()
            >>> print(der_bytes.hex())
            '020100'
        """
        ...
