"""
StreamCipher interface for stream cipher algorithms.

Reference: org.bouncycastle.crypto.StreamCipher (Bouncy Castle Java)
"""

from typing import Protocol, Union, List
from sm_bc.crypto.cipher_parameters import CipherParameters


class StreamCipher(Protocol):
    """
    Interface for stream cipher algorithms.
    
    Stream ciphers encrypt data one byte (or bit) at a time, using a keystream
    generated from the key and IV.
    
    This interface follows the Bouncy Castle Java StreamCipher interface design.
    """
    
    def get_algorithm_name(self) -> str:
        """
        Return the algorithm name.
        
        Returns:
            The name of the stream cipher algorithm
        """
        ...
    
    def init(self, for_encryption: bool, params: CipherParameters) -> None:
        """
        Initialize the stream cipher.
        
        Args:
            for_encryption: True for encryption, False for decryption
                           (typically ignored for stream ciphers as they're symmetric)
            params: The cipher parameters (typically ParametersWithIV containing KeyParameter)
        """
        ...
    
    def return_byte(self, input_byte: int) -> int:
        """
        Encrypt/decrypt a single byte.
        
        Args:
            input_byte: The byte to process (0-255)
            
        Returns:
            The processed byte (0-255)
        """
        ...
    
    def process_bytes(self, input_data: Union[bytes, bytearray, List[int]], 
                      in_off: int, length: int,
                      output: Union[bytearray, List[int]], out_off: int) -> int:
        """
        Process a block of bytes through the cipher.
        
        Args:
            input_data: The input data
            in_off: The offset into the input data
            length: The number of bytes to process
            output: The output buffer
            out_off: The offset into the output buffer
            
        Returns:
            The number of bytes written to the output buffer
        """
        ...
    
    def reset(self) -> None:
        """
        Reset the cipher to its initialized state.
        
        This allows the cipher to be reused with the same key and IV.
        """
        ...
