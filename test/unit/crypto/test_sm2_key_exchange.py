"""Unit tests for SM2 Key Exchange protocol."""

import pytest
from src.sm_bc.crypto.agreement.sm2_key_exchange import SM2KeyExchange
from src.sm_bc.crypto.params.sm2_key_exchange_private_parameters import SM2KeyExchangePrivateParameters
from src.sm_bc.crypto.params.sm2_key_exchange_public_parameters import SM2KeyExchangePublicParameters
from src.sm_bc.crypto.params.ec_domain_parameters import ECDomainParameters
from src.sm_bc.crypto.params.ec_private_key_parameters import ECPrivateKeyParameters
from src.sm_bc.crypto.params.ec_public_key_parameters import ECPublicKeyParameters
from src.sm_bc.crypto.params.parameters_with_id import ParametersWithID
from src.sm_bc.math.ec_curve import Fp
from src.sm_bc.math.ec_constants import ECConstants
from src.sm_bc.util.arrays import Arrays


# Standard SM2 Curve Parameters
SM2_ECC_P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
SM2_ECC_A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
SM2_ECC_B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
SM2_ECC_N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
SM2_ECC_H = ECConstants.ONE
SM2_ECC_GX = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
SM2_ECC_GY = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2


@pytest.fixture
def sm2_curve():
    """Create SM2 curve and domain parameters."""
    curve = Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B)
    g = curve.create_point(SM2_ECC_GX, SM2_ECC_GY)
    return ECDomainParameters(curve, g, SM2_ECC_N, SM2_ECC_H)


@pytest.fixture
def alice_keys(sm2_curve):
    """Create Alice's static and ephemeral key pairs."""
    a_private_key = 0x6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE
    a_priv = ECPrivateKeyParameters(a_private_key, sm2_curve)
    a_pub = ECPublicKeyParameters(sm2_curve.g.multiply(a_private_key), sm2_curve)

    ae_private_key = 0x83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563
    ae_priv = ECPrivateKeyParameters(ae_private_key, sm2_curve)
    ae_pub = ECPublicKeyParameters(sm2_curve.g.multiply(ae_private_key), sm2_curve)

    return a_priv, a_pub, ae_priv, ae_pub


@pytest.fixture
def bob_keys(sm2_curve):
    """Create Bob's static and ephemeral key pairs."""
    b_private_key = 0x5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53
    b_priv = ECPrivateKeyParameters(b_private_key, sm2_curve)
    b_pub = ECPublicKeyParameters(sm2_curve.g.multiply(b_private_key), sm2_curve)

    be_private_key = 0x33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80
    be_priv = ECPrivateKeyParameters(be_private_key, sm2_curve)
    be_pub = ECPublicKeyParameters(sm2_curve.g.multiply(be_private_key), sm2_curve)

    return b_priv, b_pub, be_priv, be_pub


class TestSM2KeyExchange:
    """Test SM2 Key Exchange protocol."""

    def test_basic_key_exchange_alice_to_bob(self, alice_keys, bob_keys):
        """Test basic key exchange from Alice to Bob."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        exchange = SM2KeyExchange()
        alice_user_id = b'ALICE123@YAHOO.COM'
        bob_user_id = b'BILL456@YAHOO.COM'

        # Alice initiates
        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)
        exchange.init(ParametersWithID(alice_priv_params, alice_user_id))

        # Alice calculates key using Bob's public parameters
        bob_pub_params = SM2KeyExchangePublicParameters(b_pub, be_pub)
        key1 = exchange.calculate_key(128, ParametersWithID(bob_pub_params, bob_user_id))

        assert len(key1) == 16  # 128 bits = 16 bytes
        assert isinstance(key1, bytes)

    def test_basic_key_exchange_bob_to_alice(self, alice_keys, bob_keys):
        """Test basic key exchange from Bob to Alice."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        exchange = SM2KeyExchange()
        alice_user_id = b'ALICE123@YAHOO.COM'
        bob_user_id = b'BILL456@YAHOO.COM'

        # Bob responds
        bob_priv_params = SM2KeyExchangePrivateParameters(False, b_priv, be_priv)
        exchange.init(ParametersWithID(bob_priv_params, bob_user_id))

        # Bob calculates key using Alice's public parameters
        alice_pub_params = SM2KeyExchangePublicParameters(a_pub, ae_pub)
        key2 = exchange.calculate_key(128, ParametersWithID(alice_pub_params, alice_user_id))

        assert len(key2) == 16  # 128 bits = 16 bytes
        assert isinstance(key2, bytes)

    def test_both_parties_produce_same_key(self, alice_keys, bob_keys):
        """Test that both parties produce the same shared key."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        alice_exchange = SM2KeyExchange()
        bob_exchange = SM2KeyExchange()

        alice_user_id = b'ALICE123@YAHOO.COM'
        bob_user_id = b'BILL456@YAHOO.COM'

        # Alice initiates key exchange
        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)
        alice_exchange.init(ParametersWithID(alice_priv_params, alice_user_id))
        bob_pub_params = SM2KeyExchangePublicParameters(b_pub, be_pub)
        alice_key = alice_exchange.calculate_key(128, ParametersWithID(bob_pub_params, bob_user_id))

        # Bob's exchange
        bob_priv_params = SM2KeyExchangePrivateParameters(False, b_priv, be_priv)
        bob_exchange.init(ParametersWithID(bob_priv_params, bob_user_id))
        alice_pub_params = SM2KeyExchangePublicParameters(a_pub, ae_pub)
        bob_key = bob_exchange.calculate_key(128, ParametersWithID(alice_pub_params, alice_user_id))

        # Keys should be identical
        assert Arrays.are_equal(alice_key, bob_key)

    def test_key_exchange_with_confirmation_bob_side(self, alice_keys, bob_keys):
        """Test key exchange with confirmation from Bob's side."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        exchange = SM2KeyExchange()
        bob_priv_params = SM2KeyExchangePrivateParameters(False, b_priv, be_priv)
        exchange.init(ParametersWithID(bob_priv_params, b'BILL456@YAHOO.COM'))

        alice_pub_params = SM2KeyExchangePublicParameters(a_pub, ae_pub)
        result = exchange.calculate_key_with_confirmation(
            128, None, ParametersWithID(alice_pub_params, b'ALICE123@YAHOO.COM')
        )

        # Bob is responder, so returns [key, s1, s2]
        assert len(result) == 3
        assert len(result[0]) == 16  # key should be 16 bytes
        assert len(result[1]) == 32  # s1 should be 32 bytes (SM3 digest)
        assert len(result[2]) == 32  # s2 should be 32 bytes (SM3 digest)

    def test_key_exchange_with_confirmation_alice_side(self, alice_keys, bob_keys):
        """Test key exchange with confirmation from Alice's side."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        alice_exchange = SM2KeyExchange()
        bob_exchange = SM2KeyExchange()

        alice_user_id = b'ALICE123@YAHOO.COM'
        bob_user_id = b'BILL456@YAHOO.COM'

        # Bob creates confirmation tag first (as responder)
        bob_priv_params = SM2KeyExchangePrivateParameters(False, b_priv, be_priv)
        bob_exchange.init(ParametersWithID(bob_priv_params, bob_user_id))
        alice_pub_params = SM2KeyExchangePublicParameters(a_pub, ae_pub)
        bob_result = bob_exchange.calculate_key_with_confirmation(
            128, None, ParametersWithID(alice_pub_params, alice_user_id)
        )

        # Alice responds with confirmation (as initiator)
        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)
        alice_exchange.init(ParametersWithID(alice_priv_params, alice_user_id))
        bob_pub_params = SM2KeyExchangePublicParameters(b_pub, be_pub)
        alice_result = alice_exchange.calculate_key_with_confirmation(
            128, bob_result[1], ParametersWithID(bob_pub_params, bob_user_id)
        )

        # Bob is responder: returns [key, s1, s2]
        # Alice is initiator: returns [key, s2]
        assert len(bob_result) == 3
        assert len(alice_result) == 2

        # Keys should be the same
        assert Arrays.are_equal(bob_result[0], alice_result[0])

    def test_confirmation_tags_match(self, alice_keys, bob_keys):
        """Test that confirmation tags match between parties."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        alice_exchange = SM2KeyExchange()
        bob_exchange = SM2KeyExchange()

        alice_user_id = b'ALICE123@YAHOO.COM'
        bob_user_id = b'BILL456@YAHOO.COM'

        # Bob exchange (responder)
        bob_priv_params = SM2KeyExchangePrivateParameters(False, b_priv, be_priv)
        bob_exchange.init(ParametersWithID(bob_priv_params, bob_user_id))
        alice_pub_params = SM2KeyExchangePublicParameters(a_pub, ae_pub)
        bob_result = bob_exchange.calculate_key_with_confirmation(
            128, None, ParametersWithID(alice_pub_params, alice_user_id)
        )

        # Alice exchange (initiator with Bob's confirmation)
        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)
        alice_exchange.init(ParametersWithID(alice_priv_params, alice_user_id))
        bob_pub_params = SM2KeyExchangePublicParameters(b_pub, be_pub)
        alice_result = alice_exchange.calculate_key_with_confirmation(
            128, bob_result[1], ParametersWithID(bob_pub_params, bob_user_id)
        )

        # Validate key agreement
        assert Arrays.are_equal(bob_result[0], alice_result[0])
        # Validate confirmation protocol - both should produce same S2 tag
        assert Arrays.are_equal(bob_result[2], alice_result[1])

    def test_parameter_validation(self, alice_keys, bob_keys):
        """Test parameter validation."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)
        bob_priv_params = SM2KeyExchangePrivateParameters(False, b_priv, be_priv)

        assert alice_priv_params.is_initiator() == True
        assert bob_priv_params.is_initiator() == False
        assert alice_priv_params.get_static_private_key() == a_priv
        assert alice_priv_params.get_ephemeral_private_key() == ae_priv

    def test_public_parameter_validation(self, alice_keys, bob_keys):
        """Test public parameter validation."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        alice_pub_params = SM2KeyExchangePublicParameters(a_pub, ae_pub)
        bob_pub_params = SM2KeyExchangePublicParameters(b_pub, be_pub)

        assert alice_pub_params.get_static_public_key() == a_pub
        assert alice_pub_params.get_ephemeral_public_key() == ae_pub
        assert bob_pub_params.get_static_public_key() == b_pub
        assert bob_pub_params.get_ephemeral_public_key() == be_pub

    def test_different_key_lengths(self, alice_keys, bob_keys):
        """Test different key lengths."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        exchange = SM2KeyExchange()
        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)
        exchange.init(ParametersWithID(alice_priv_params, b'ALICE123@YAHOO.COM'))

        bob_pub_params = SM2KeyExchangePublicParameters(b_pub, be_pub)

        key64 = exchange.calculate_key(64, ParametersWithID(bob_pub_params, b'BILL456@YAHOO.COM'))
        key256 = exchange.calculate_key(256, ParametersWithID(bob_pub_params, b'BILL456@YAHOO.COM'))

        assert len(key64) == 8   # 64 bits = 8 bytes
        assert len(key256) == 32  # 256 bits = 32 bytes

    def test_error_invalid_key_length(self, alice_keys, bob_keys):
        """Test error for invalid key length."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        exchange = SM2KeyExchange()
        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)
        exchange.init(ParametersWithID(alice_priv_params, b'ALICE123@YAHOO.COM'))

        bob_pub_params = SM2KeyExchangePublicParameters(b_pub, be_pub)

        with pytest.raises(ValueError, match="Key length must be positive"):
            exchange.calculate_key(0, ParametersWithID(bob_pub_params, b'BILL456@YAHOO.COM'))

    def test_empty_user_ids(self, alice_keys):
        """Test handling of empty user IDs."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys

        exchange = SM2KeyExchange()
        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)

        # Should not raise for empty user ID
        exchange.init(ParametersWithID(alice_priv_params, bytes()))

    def test_different_user_ids_produce_different_keys(self, alice_keys, bob_keys):
        """Test that different user IDs produce different keys."""
        a_priv, a_pub, ae_priv, ae_pub = alice_keys
        b_priv, b_pub, be_priv, be_pub = bob_keys

        exchange1 = SM2KeyExchange()
        exchange2 = SM2KeyExchange()

        alice_priv_params = SM2KeyExchangePrivateParameters(True, a_priv, ae_priv)
        bob_pub_params = SM2KeyExchangePublicParameters(b_pub, be_pub)

        exchange1.init(ParametersWithID(alice_priv_params, b'ALICE123@YAHOO.COM'))
        key1 = exchange1.calculate_key(128, ParametersWithID(bob_pub_params, b'BILL456@YAHOO.COM'))

        exchange2.init(ParametersWithID(alice_priv_params, b'ALICE456@YAHOO.COM'))
        key2 = exchange2.calculate_key(128, ParametersWithID(bob_pub_params, b'BILL789@YAHOO.COM'))

        # Different user IDs should produce different keys
        assert not Arrays.are_equal(key1, key2)
