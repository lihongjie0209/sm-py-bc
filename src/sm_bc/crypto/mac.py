"""
Mac (Message Authentication Code) interface.

Reference: org.bouncycastle.crypto.Mac (Bouncy Castle Java)
"""

from typing import Protocol, Union, List
from sm_bc.crypto.cipher_parameters import CipherParameters


class Mac(Protocol):
    """
    Interface for Message Authentication Code (MAC) algorithms.
    
    A MAC provides a way to check the integrity and authenticity of data
    using a secret key.
    
    This interface follows the Bouncy Castle Java Mac interface design.
    """
    
    def get_algorithm_name(self) -> str:
        """
        Return the algorithm name.
        
        Returns:
            The name of the MAC algorithm
        """
        ...
    
    def get_mac_size(self) -> int:
        """
        Return the size (in bytes) of the MAC this cipher generates.
        
        Returns:
            The MAC size in bytes
        """
        ...
    
    def init(self, params: CipherParameters) -> None:
        """
        Initialize the MAC with the given parameters.
        
        Args:
            params: The cipher parameters (typically KeyParameter)
        """
        ...
    
    def update(self, input_byte: int) -> None:
        """
        Process a single byte through the MAC.
        
        Args:
            input_byte: The byte to process (0-255)
        """
        ...
    
    def update_bytes(self, input_data: Union[bytes, bytearray, List[int]], 
                     offset: int, length: int) -> None:
        """
        Process a block of bytes through the MAC.
        
        Args:
            input_data: The input data
            offset: The offset into the input data to start
            length: The number of bytes to process
        """
        ...
    
    def do_final(self, output: Union[bytearray, List[int]], offset: int) -> int:
        """
        Complete the MAC computation and output the result.
        
        The MAC is reset after calling this method.
        
        Args:
            output: The output buffer
            offset: The offset into the output buffer
            
        Returns:
            The number of bytes written to the output buffer
        """
        ...
    
    def reset(self) -> None:
        """
        Reset the MAC to its initialized state.
        
        This allows the MAC to be reused with the same key.
        """
        ...
