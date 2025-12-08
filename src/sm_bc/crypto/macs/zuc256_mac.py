"""
ZUC-256 MAC (256-EIA3) implementation.

ZUC-256 MAC is the enhanced integrity algorithm for 3GPP 5G,
also known as 256-EIA3 (Evolved Packet System Integrity Algorithm 3).

Standards: 3GPP TS 35.222
Reference:
- org.bouncycastle.crypto.macs.Zuc256Mac (Bouncy Castle Java)
- src/crypto/macs/ZUC256MAC.ts (sm-js-bc)
"""

from typing import Union, List
from sm_bc.crypto.mac import Mac
from sm_bc.crypto.engines.zuc256_engine import ZUC256Engine
from sm_bc.crypto.cipher_parameters import CipherParameters
from sm_bc.crypto.params.key_parameter import KeyParameter
from sm_bc.crypto.params.parameters_with_iv import ParametersWithIV
from sm_bc.exceptions import DataLengthException


class ZUC256MAC(Mac):
    """
    ZUC-256 based Message Authentication Code (256-EIA3).
    
    This is the 3GPP 5G enhanced integrity algorithm that uses ZUC-256
    stream cipher to generate a MAC tag with higher security.
    
    The MAC can be 64 or 128 bits (8 or 16 bytes).
    
    Example usage:
        >>> from sm_bc.crypto.macs import ZUC256MAC
        >>> from sm_bc.crypto.params import KeyParameter, ParametersWithIV
        >>> import secrets
        >>> 
        >>> key = secrets.token_bytes(32)  # 256-bit key
        >>> iv = secrets.token_bytes(23)   # 184-bit IV
        >>> 
        >>> mac = ZUC256MAC()  # Default 128-bit MAC
        >>> mac.init(ParametersWithIV(KeyParameter(key), iv))
        >>> 
        >>> message = b"Hello, ZUC-256 MAC!"
        >>> mac.update_bytes(message, 0, len(message))
        >>> 
        >>> tag = bytearray(mac.get_mac_size())
        >>> mac.do_final(tag, 0)
    """
    
    def __init__(self, mac_bits: int = 128):
        """
        Initialize ZUC-256 MAC.
        
        Args:
            mac_bits: MAC output size in bits (64 or 128).
                     Default is 128 bits (16 bytes).
        
        Raises:
            ValueError: If mac_bits is not 64 or 128
        """
        if mac_bits not in (64, 128):
            raise ValueError(f"ZUC-256 MAC bits must be 64 or 128, got {mac_bits}")
        
        self.mac_bits = mac_bits
        self.mac_bytes = mac_bits // 8
        
        # ZUC-256 engine for keystream generation
        self.zuc_engine = ZUC256Engine(mac_bits=mac_bits)
        
        # Message buffer
        self.message: bytearray = bytearray()
        
        # Working key and IV for reset
        self.working_key: bytes = b''
        self.working_iv: bytes = b''
    
    def get_algorithm_name(self) -> str:
        """
        Get the algorithm name.
        
        Returns:
            The algorithm name
        """
        return f'ZUC-256-MAC-{self.mac_bits}'
    
    def get_mac_size(self) -> int:
        """
        Get the MAC size in bytes.
        
        Returns:
            The MAC size in bytes (8 or 16)
        """
        return self.mac_bytes
    
    def init(self, params: CipherParameters) -> None:
        """
        Initialize the MAC with key and IV.
        
        Args:
            params: Must be ParametersWithIV containing a KeyParameter
            
        Raises:
            ValueError: If params are invalid
        """
        if not isinstance(params, ParametersWithIV):
            raise ValueError("ZUC-256 MAC requires ParametersWithIV")
        
        key_param = params.get_parameters()
        if not isinstance(key_param, KeyParameter):
            raise ValueError("ZUC-256 MAC requires KeyParameter")
        
        self.working_key = bytes(key_param.get_key())
        self.working_iv = bytes(params.get_iv())
        
        # Validate key size (must be 256 bits = 32 bytes)
        if len(self.working_key) != 32:
            raise ValueError(f"ZUC-256 MAC requires 256-bit key, got {len(self.working_key)*8} bits")
        
        # Validate IV size (must be 184 bits = 23 bytes or 200 bits = 25 bytes)
        if len(self.working_iv) not in (23, 25):
            raise ValueError(
                f"ZUC-256 MAC requires 184-bit (23 bytes) or 200-bit (25 bytes) IV, "
                f"got {len(self.working_iv)*8} bits"
            )
        
        # Initialize ZUC-256 engine
        self.zuc_engine.init(True, params)
        
        # Reset message buffer
        self.message = bytearray()
    
    def update(self, input_byte: int) -> None:
        """
        Process a single byte.
        
        Args:
            input_byte: The byte to process (0-255)
        """
        self.message.append(input_byte & 0xFF)
    
    def update_bytes(self, input_data: Union[bytes, bytearray, List[int]], 
                     offset: int, length: int) -> None:
        """
        Process a block of bytes.
        
        Args:
            input_data: The input data
            offset: The offset into the input data
            length: The number of bytes to process
        """
        if length < 0:
            raise ValueError("Length cannot be negative")
        
        if offset < 0 or offset + length > len(input_data):
            raise DataLengthException("Input buffer too short")
        
        # Append to message buffer
        self.message.extend(input_data[offset:offset + length])
    
    def do_final(self, output: Union[bytearray, List[int]], offset: int) -> int:
        """
        Complete the MAC computation and output the result.
        
        Args:
            output: The output buffer
            offset: The offset into the output buffer
            
        Returns:
            The number of bytes written (mac_bytes)
            
        Raises:
            DataLengthException: If output buffer is too small
        """
        if offset < 0 or offset + self.mac_bytes > len(output):
            raise DataLengthException("Output buffer too short for MAC")
        
        # Calculate MAC using ZUC-256 keystream
        mac_value = self._calculate_mac()
        
        # Write MAC to output (big-endian)
        if self.mac_bytes == 8:  # 64-bit MAC
            for i in range(8):
                output[offset + i] = (mac_value >> (56 - i * 8)) & 0xFF
        else:  # 128-bit MAC
            for i in range(16):
                output[offset + i] = (mac_value >> (120 - i * 8)) & 0xFF
        
        # Reset for next MAC computation
        self.reset()
        
        return self.mac_bytes
    
    def reset(self) -> None:
        """
        Reset the MAC to its initialized state.
        """
        self.message = bytearray()
        
        # Reinitialize ZUC-256 engine if we have key and IV
        if self.working_key and self.working_iv:
            params = ParametersWithIV(
                KeyParameter(self.working_key),
                self.working_iv
            )
            self.zuc_engine.init(True, params)
    
    def _calculate_mac(self) -> int:
        """
        Calculate the MAC value using ZUC-256 keystream.
        
        This implements the 256-EIA3 algorithm from 3GPP TS 35.222.
        
        Returns:
            The MAC value as an integer (64-bit or 128-bit)
        """
        # Get message length in bits
        message_len_bits = len(self.message) * 8
        
        # Generate keystream words using ZUC-256
        # We need enough keystream to cover the message
        num_words = (message_len_bits + 31) // 32  # Round up
        
        # For 128-bit MAC, we need extra words
        if self.mac_bytes == 16:
            num_words = max(num_words, 4)  # At least 4 words for 128-bit MAC
        
        # Generate keystream
        keystream = bytearray(num_words * 4)
        zero_input = bytes(num_words * 4)
        self.zuc_engine.process_bytes(zero_input, 0, len(zero_input), keystream, 0)
        
        # Initialize MAC accumulator
        mac = 0
        
        # Process message in 32-bit words
        for i in range(num_words):
            # Get 32-bit word from message (big-endian)
            msg_word = 0
            for j in range(4):
                byte_idx = i * 4 + j
                if byte_idx < len(self.message):
                    msg_word = (msg_word << 8) | self.message[byte_idx]
                else:
                    msg_word = msg_word << 8  # Pad with zeros
            
            # Get 32-bit word from keystream (big-endian)
            key_word = 0
            for j in range(4):
                key_word = (key_word << 8) | keystream[i * 4 + j]
            
            # XOR and accumulate
            if self.mac_bytes == 8:
                # 64-bit MAC
                if i < 2:
                    mac = (mac << 32) | ((msg_word ^ key_word) & 0xFFFFFFFF)
                else:
                    # Mix in remaining words
                    mac ^= ((msg_word ^ key_word) & 0xFFFFFFFF)
            else:
                # 128-bit MAC
                if i < 4:
                    mac = (mac << 32) | ((msg_word ^ key_word) & 0xFFFFFFFF)
                else:
                    # Mix in remaining words
                    mac ^= ((msg_word ^ key_word) & 0xFFFFFFFF)
        
        # Return appropriate size
        if self.mac_bytes == 8:
            return mac & 0xFFFFFFFFFFFFFFFF
        else:
            return mac & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
