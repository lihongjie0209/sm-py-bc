"""
HMAC (Hash-based Message Authentication Code) implementation.

Reference: 
- RFC 2104: HMAC: Keyed-Hashing for Message Authentication
- org.bouncycastle.crypto.macs.HMac (Bouncy Castle Java)
- src/crypto/macs/HMac.ts (sm-js-bc)
"""

from typing import Union, List
from sm_bc.crypto.mac import Mac
from sm_bc.crypto.digest import Digest
from sm_bc.crypto.extended_digest import ExtendedDigest
from sm_bc.crypto.cipher_parameters import CipherParameters
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.exceptions import DataLengthException


class HMac(Mac):
    """
    HMAC implementation based on a hash function (RFC 2104).
    
    This implementation follows the Bouncy Castle Java design and supports
    any underlying digest algorithm.
    
    HMAC formula:
        HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
    
    Where:
        H = underlying hash function
        K = secret key
        m = message
        || = concatenation
        ⊕ = XOR
        ipad = 0x36 repeated blockLength times
        opad = 0x5C repeated blockLength times
    
    Example usage:
        >>> from sm_bc.crypto.digests import SM3Digest
        >>> from sm_bc.crypto.macs import HMac
        >>> from sm_bc.crypto.params import KeyParameter
        >>> 
        >>> hmac = HMac(SM3Digest())
        >>> key = b"my-secret-key"
        >>> hmac.init(KeyParameter(key))
        >>> 
        >>> message = b"Hello, HMAC-SM3!"
        >>> hmac.update_bytes(message, 0, len(message))
        >>> 
        >>> mac = bytearray(hmac.get_mac_size())
        >>> hmac.do_final(mac, 0)
        >>> print(mac.hex())
    """
    
    IPAD = 0x36
    OPAD = 0x5C
    
    def __init__(self, digest: Digest):
        """
        Create an HMAC instance with the given digest.
        
        Args:
            digest: The underlying hash function (e.g., SM3Digest)
        """
        self.digest = digest
        self.digest_size = digest.get_digest_size()
        
        # Get the block length from the digest
        # ExtendedDigest provides get_byte_length(), fallback to 64 for basic Digest
        if isinstance(digest, ExtendedDigest):
            self.block_length = digest.get_byte_length()
        else:
            # Default to 64 bytes (SHA-1, SHA-256, SM3)
            self.block_length = 64
        
        self.input_pad = bytearray(self.block_length)
        self.output_buf = bytearray(self.block_length + self.digest_size)
    
    def get_algorithm_name(self) -> str:
        """
        Get the algorithm name.
        
        Returns:
            The algorithm name in format "HMac/{digest-name}"
        """
        return f"HMac/{self.digest.get_algorithm_name()}"
    
    def get_mac_size(self) -> int:
        """
        Get the MAC size (same as the underlying digest size).
        
        Returns:
            The MAC size in bytes
        """
        return self.digest_size
    
    def init(self, params: CipherParameters) -> None:
        """
        Initialize the HMAC with a key.
        
        Args:
            params: The key parameter (must be KeyParameter)
            
        Raises:
            ValueError: If params is not a KeyParameter
        """
        self.digest.reset()
        
        if not isinstance(params, KeyParameter):
            raise ValueError('HMac requires KeyParameter')
        
        key = params.key
        key_length = len(key)
        
        # If the key is longer than the block size, hash it first
        if key_length > self.block_length:
            self.digest.update_bytes(key, 0, key_length)
            self.digest.do_final(self.input_pad, 0)
            key_length = self.digest_size
        else:
            # Copy the key to input_pad
            self.input_pad[0:key_length] = key[0:key_length]
        
        # Pad the key with zeros if necessary
        for i in range(key_length, self.block_length):
            self.input_pad[i] = 0
        
        # Copy input_pad to output_buf (first block_length bytes)
        self.output_buf[0:self.block_length] = self.input_pad[0:self.block_length]
        
        # XOR the key with ipad for the input padding
        self._xor_pad(self.input_pad, self.block_length, self.IPAD)
        
        # XOR the key with opad for the output padding
        self._xor_pad(self.output_buf, self.block_length, self.OPAD)
        
        # Initialize the inner hash
        self.digest.update_bytes(self.input_pad, 0, len(self.input_pad))
    
    def _xor_pad(self, pad: bytearray, length: int, n: int) -> None:
        """
        XOR a pad with a specific byte value.
        
        Args:
            pad: The padding buffer
            length: The length to XOR
            n: The byte value to XOR with
        """
        for i in range(length):
            pad[i] ^= n
    
    def update(self, input_byte: int) -> None:
        """
        Update the MAC with a single byte.
        
        Args:
            input_byte: The input byte (0-255)
        """
        self.digest.update(input_byte)
    
    def update_bytes(self, input_data: Union[bytes, bytearray, List[int]], 
                     offset: int, length: int) -> None:
        """
        Update the MAC with multiple bytes.
        
        Args:
            input_data: The input byte array
            offset: The offset into the input array
            length: The number of bytes to process
        """
        self.digest.update_bytes(input_data, offset, length)
    
    def do_final(self, output: Union[bytearray, List[int]], offset: int) -> int:
        """
        Complete the MAC calculation.
        
        Args:
            output: The output buffer
            offset: The offset into the output buffer
            
        Returns:
            The number of bytes written
            
        Raises:
            DataLengthException: If the output buffer is too small
        """
        if len(output) - offset < self.digest_size:
            raise DataLengthException('Output buffer too small')
        
        # Complete the inner hash: H(K ⊕ ipad || message)
        self.digest.do_final(self.output_buf, self.block_length)
        
        # Compute the outer hash: H(K ⊕ opad || inner_hash)
        self.digest.update_bytes(self.output_buf, 0, self.block_length + self.digest_size)
        result = self.digest.do_final(output, offset)
        
        # Reset for next use
        # Re-initialize the inner hash with the input pad
        self.digest.update_bytes(self.input_pad, 0, len(self.input_pad))
        
        return result
    
    def reset(self) -> None:
        """
        Reset the MAC to its initialized state.
        
        This allows the MAC to be reused with the same key.
        """
        # Reset the underlying digest
        self.digest.reset()
        
        # Re-initialize with the input pad (K ⊕ ipad)
        self.digest.update_bytes(self.input_pad, 0, len(self.input_pad))
