"""Tests for SM2 Key Exchange implementation."""

import pytest
from sm_bc.crypto.agreement.sm2_key_exchange import SM2KeyExchange
from sm_bc.crypto.params.sm2_key_exchange_private_parameters import SM2KeyExchangePrivateParameters
from sm_bc.crypto.params.sm2_key_exchange_public_parameters import SM2KeyExchangePublicParameters
from sm_bc.crypto.params.ec_domain_parameters import ECDomainParameters
from sm_bc.crypto.params.ec_private_key_parameters import ECPrivateKeyParameters
from sm_bc.crypto.params.ec_public_key_parameters import ECPublicKeyParameters
from sm_bc.crypto.params.parameters_with_id import ParametersWithID
from sm_bc.math.ec_curve import Fp as ECCurveFp
from sm_bc.math.ec_constants import ECConstants
from sm_bc.util.arrays import Arrays


class TestSM2KeyExchange:
    """Test suite for SM2 Key Exchange."""
    
    # Standard SM2 Curve Parameters
    SM2_ECC_P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
    SM2_ECC_A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
    SM2_ECC_B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
    SM2_ECC_N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
    SM2_ECC_H = ECConstants.ONE
    SM2_ECC_GX = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
    SM2_ECC_GY = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test fixtures."""
        # Create the SM2 curve
        self.curve = ECCurveFp(self.SM2_ECC_P, self.SM2_ECC_A, self.SM2_ECC_B)
        self.g = self.curve.create_point(self.SM2_ECC_GX, self.SM2_ECC_GY)
        self.domain_params = ECDomainParameters(self.curve, self.g, self.SM2_ECC_N, self.SM2_ECC_H)
        
        # Alice's static key pair
        a_private_key = 0x6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE
        self.a_priv = ECPrivateKeyParameters(a_private_key, self.domain_params)
        self.a_pub = ECPublicKeyParameters(self.g.multiply(a_private_key), self.domain_params)
        
        # Alice's ephemeral key pair
        ae_private_key = 0x83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563
        self.ae_priv = ECPrivateKeyParameters(ae_private_key, self.domain_params)
        self.ae_pub = ECPublicKeyParameters(self.g.multiply(ae_private_key), self.domain_params)
        
        # Bob's static key pair
        b_private_key = 0x5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53
        self.b_priv = ECPrivateKeyParameters(b_private_key, self.domain_params)
        self.b_pub = ECPublicKeyParameters(self.g.multiply(b_private_key), self.domain_params)
        
        # Bob's ephemeral key pair
        be_private_key = 0x33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80
        self.be_priv = ECPrivateKeyParameters(be_private_key, self.domain_params)
        self.be_pub = ECPublicKeyParameters(self.g.multiply(be_private_key), self.domain_params)
    
    def test_basic_key_exchange_alice_to_bob(self):
        """Test basic key exchange from Alice to Bob."""
        exchange = SM2KeyExchange()
        alice_user_id = 'ALICE123@YAHOO.COM'.encode()
        bob_user_id = 'BILL456@YAHOO.COM'.encode()
        
        # Alice initiates
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        exchange.init(ParametersWithID(alice_priv_params, alice_user_id))
        
        # Alice calculates key using Bob's public parameters  
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        key1 = exchange.calculate_key(128, ParametersWithID(bob_pub_params, bob_user_id))
        
        assert len(key1) == 16  # 128 bits = 16 bytes
        assert isinstance(key1, bytes)
    
    def test_basic_key_exchange_bob_to_alice(self):
        """Test basic key exchange from Bob to Alice."""
        exchange = SM2KeyExchange()
        alice_user_id = 'ALICE123@YAHOO.COM'.encode()
        bob_user_id = 'BILL456@YAHOO.COM'.encode()
        
        # Bob responds
        bob_priv_params = SM2KeyExchangePrivateParameters(False, self.b_priv, self.be_priv)  
        exchange.init(ParametersWithID(bob_priv_params, bob_user_id))
        
        # Bob calculates key using Alice's public parameters
        alice_pub_params = SM2KeyExchangePublicParameters(self.a_pub, self.ae_pub)
        key2 = exchange.calculate_key(128, ParametersWithID(alice_pub_params, alice_user_id))
        
        assert len(key2) == 16  # 128 bits = 16 bytes
        assert isinstance(key2, bytes)
    
    def test_both_parties_produce_same_key(self):
        """Test that both parties produce the same key."""
        alice_exchange = SM2KeyExchange()
        bob_exchange = SM2KeyExchange()
        
        # Alice initiates key exchange
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        alice_exchange.init(ParametersWithID(alice_priv_params, 'ALICE123@YAHOO.COM'.encode()))
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        alice_key = alice_exchange.calculate_key(128, ParametersWithID(bob_pub_params, 'BILL456@YAHOO.COM'.encode()))
        
        # Bob's exchange
        bob_priv_params = SM2KeyExchangePrivateParameters(False, self.b_priv, self.be_priv)
        bob_exchange.init(ParametersWithID(bob_priv_params, 'BILL456@YAHOO.COM'.encode()))
        alice_pub_params = SM2KeyExchangePublicParameters(self.a_pub, self.ae_pub)
        bob_key = bob_exchange.calculate_key(128, ParametersWithID(alice_pub_params, 'ALICE123@YAHOO.COM'.encode()))
        
        # Keys should be identical
        assert Arrays.are_equal(alice_key, bob_key)
    
    def test_key_exchange_with_confirmation_bob_side(self):
        """Test key exchange with confirmation from Bob side."""
        exchange = SM2KeyExchange()
        bob_priv_params = SM2KeyExchangePrivateParameters(False, self.b_priv, self.be_priv)
        exchange.init(ParametersWithID(bob_priv_params, 'BILL456@YAHOO.COM'.encode()))
        
        alice_pub_params = SM2KeyExchangePublicParameters(self.a_pub, self.ae_pub)
        result = exchange.calculate_key_with_confirmation(128, None, ParametersWithID(alice_pub_params, 'ALICE123@YAHOO.COM'.encode()))
        
        # Bob is responder, so returns [key, s1, s2]
        assert len(result) == 3
        assert len(result[0]) == 16  # key should be 16 bytes
        assert len(result[1]) == 32  # s1 should be 32 bytes (SM3 digest)
        assert len(result[2]) == 32  # s2 should be 32 bytes (SM3 digest)
    
    def test_key_exchange_with_confirmation_alice_side(self):
        """Test key exchange with confirmation from Alice side."""
        alice_exchange = SM2KeyExchange()
        bob_exchange = SM2KeyExchange()
        
        # Bob creates confirmation tag first (as responder) 
        bob_priv_params = SM2KeyExchangePrivateParameters(False, self.b_priv, self.be_priv)
        bob_exchange.init(ParametersWithID(bob_priv_params, 'BILL456@YAHOO.COM'.encode()))
        alice_pub_params = SM2KeyExchangePublicParameters(self.a_pub, self.ae_pub)
        bob_result = bob_exchange.calculate_key_with_confirmation(128, None, ParametersWithID(alice_pub_params, 'ALICE123@YAHOO.COM'.encode()))
        
        # Alice responds with confirmation (as initiator)
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        alice_exchange.init(ParametersWithID(alice_priv_params, 'ALICE123@YAHOO.COM'.encode()))
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        alice_result = alice_exchange.calculate_key_with_confirmation(128, bob_result[1], ParametersWithID(bob_pub_params, 'BILL456@YAHOO.COM'.encode()))
        
        # Bob is responder: returns [key, s1, s2]  
        # Alice is initiator: returns [key, s2]
        assert len(bob_result) == 3
        assert len(alice_result) == 2
        
        # Keys should be the same
        assert Arrays.are_equal(bob_result[0], alice_result[0])
    
    def test_confirmation_tags_match_between_parties(self):
        """Test that confirmation tags match between parties."""
        alice_exchange = SM2KeyExchange()
        bob_exchange = SM2KeyExchange()
        
        # Bob exchange (responder)
        bob_priv_params = SM2KeyExchangePrivateParameters(False, self.b_priv, self.be_priv)
        bob_exchange.init(ParametersWithID(bob_priv_params, 'BILL456@YAHOO.COM'.encode()))
        alice_pub_params = SM2KeyExchangePublicParameters(self.a_pub, self.ae_pub)
        bob_result = bob_exchange.calculate_key_with_confirmation(128, None, ParametersWithID(alice_pub_params, 'ALICE123@YAHOO.COM'.encode()))
        
        # Alice exchange (initiator with Bob's confirmation)
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        alice_exchange.init(ParametersWithID(alice_priv_params, 'ALICE123@YAHOO.COM'.encode()))
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        alice_result = alice_exchange.calculate_key_with_confirmation(128, bob_result[1], ParametersWithID(bob_pub_params, 'BILL456@YAHOO.COM'.encode()))
        
        # Validate key agreement
        assert Arrays.are_equal(bob_result[0], alice_result[0])
        # Validate confirmation protocol - both should produce same S2 tag
        assert Arrays.are_equal(bob_result[2], alice_result[1])  # Bob's S2 should match Alice's S2
    
    def test_parameter_validation_private_parameters(self):
        """Test validation of private parameters construction."""
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        bob_priv_params = SM2KeyExchangePrivateParameters(False, self.b_priv, self.be_priv)
        
        assert alice_priv_params.is_initiator() is True
        assert bob_priv_params.is_initiator() is False
        assert alice_priv_params.get_static_private_key() is self.a_priv
        assert alice_priv_params.get_ephemeral_private_key() is self.ae_priv
    
    def test_parameter_validation_public_parameters(self):
        """Test validation of public parameters construction."""
        alice_pub_params = SM2KeyExchangePublicParameters(self.a_pub, self.ae_pub)
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        
        assert alice_pub_params.get_static_public_key() is self.a_pub
        assert alice_pub_params.get_ephemeral_public_key() is self.ae_pub
        assert bob_pub_params.get_static_public_key() is self.b_pub
        assert bob_pub_params.get_ephemeral_public_key() is self.be_pub
    
    def test_different_key_lengths(self):
        """Test handling of different key lengths."""
        exchange = SM2KeyExchange()
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        exchange.init(ParametersWithID(alice_priv_params, 'ALICE123@YAHOO.COM'.encode()))
        
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        
        key64 = exchange.calculate_key(64, ParametersWithID(bob_pub_params, 'BILL456@YAHOO.COM'.encode()))
        
        # Re-init for second key generation
        exchange.init(ParametersWithID(alice_priv_params, 'ALICE123@YAHOO.COM'.encode()))
        key256 = exchange.calculate_key(256, ParametersWithID(bob_pub_params, 'BILL456@YAHOO.COM'.encode()))
        
        assert len(key64) == 8   # 64 bits = 8 bytes
        assert len(key256) == 32  # 256 bits = 32 bytes
    
    def test_error_not_initialized(self):
        """Test error when not initialized."""
        exchange = SM2KeyExchange()
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        
        with pytest.raises(Exception):
            exchange.calculate_key(128, ParametersWithID(bob_pub_params, 'BILL456@YAHOO.COM'.encode()))
    
    def test_error_invalid_key_length(self):
        """Test error for invalid key length."""
        exchange = SM2KeyExchange()
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        exchange.init(ParametersWithID(alice_priv_params, 'ALICE123@YAHOO.COM'.encode()))
        
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        
        with pytest.raises(ValueError):
            exchange.calculate_key(0, ParametersWithID(bob_pub_params, 'BILL456@YAHOO.COM'.encode()))
    
    def test_empty_user_ids(self):
        """Test handling of empty user IDs."""
        exchange = SM2KeyExchange()
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        
        # Should not raise for empty user ID
        exchange.init(ParametersWithID(alice_priv_params, bytes()))
        
        # Should be able to calculate key
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        key = exchange.calculate_key(128, ParametersWithID(bob_pub_params, bytes()))
        assert len(key) == 16
    
    def test_different_curve_points(self):
        """Test with different curve point for variety."""
        alt_private_key = 0x1234567890ABCDEF
        alt_priv = ECPrivateKeyParameters(alt_private_key, self.domain_params)
        alt_pub = ECPublicKeyParameters(self.g.multiply(alt_private_key), self.domain_params)
        
        exchange = SM2KeyExchange()
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        exchange.init(ParametersWithID(alice_priv_params, 'ALICE123@YAHOO.COM'.encode()))
        
        alt_pub_params = SM2KeyExchangePublicParameters(alt_pub, self.be_pub)
        key = exchange.calculate_key(128, ParametersWithID(alt_pub_params, 'ALT456@YAHOO.COM'.encode()))
        
        assert len(key) == 16
        assert isinstance(key, bytes)
    
    def test_different_user_ids_produce_different_keys(self):
        """Test that different user IDs produce different keys."""
        exchange1 = SM2KeyExchange()
        exchange2 = SM2KeyExchange()
        
        alice_priv_params = SM2KeyExchangePrivateParameters(True, self.a_priv, self.ae_priv)
        bob_pub_params = SM2KeyExchangePublicParameters(self.b_pub, self.be_pub)
        
        exchange1.init(ParametersWithID(alice_priv_params, 'ALICE123@YAHOO.COM'.encode()))
        key1 = exchange1.calculate_key(128, ParametersWithID(bob_pub_params, 'BILL456@YAHOO.COM'.encode()))
        
        exchange2.init(ParametersWithID(alice_priv_params, 'ALICE456@YAHOO.COM'.encode()))
        key2 = exchange2.calculate_key(128, ParametersWithID(bob_pub_params, 'BILL789@YAHOO.COM'.encode()))
        
        # Different user IDs should produce different keys
        assert not Arrays.are_equal(key1, key2)
