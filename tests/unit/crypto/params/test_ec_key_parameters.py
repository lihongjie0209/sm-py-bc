"""
Unit tests for ECKeyParameters
Aligned with sm-js-bc/test/unit/crypto/params/ECKeyParameters.test.ts
"""
import pytest
from sm_bc.crypto.params.ec_public_key_parameters import ECPublicKeyParameters
from sm_bc.crypto.params.ec_private_key_parameters import ECPrivateKeyParameters
from sm_bc.crypto.SM2 import SM2


class TestECPublicKeyParameters:
    """Test ECPublicKeyParameters class"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test fixtures"""
        self.domain_params = SM2.get_parameters()
        self.curve = self.domain_params.get_curve()
        self.G = self.domain_params.get_G()
        
        # Test key values
        self.test_private_key = 123456789
        self.test_public_point = self.G.multiply(self.test_private_key)
    
    def test_create_public_key_parameters_correctly(self):
        """Should create public key parameters correctly"""
        pub_key = ECPublicKeyParameters(self.test_public_point, self.domain_params)
        
        assert pub_key.get_Q() is self.test_public_point
        assert pub_key.get_parameters() is self.domain_params
        assert pub_key.is_private() is False
    
    def test_work_with_sm2_curve_points(self):
        """Should work with SM2 curve points"""
        # Use the generator point itself
        pub_key = ECPublicKeyParameters(self.G, self.domain_params)
        
        assert pub_key.get_Q() is self.G
        assert pub_key.get_parameters().get_curve() is self.curve
        assert pub_key.is_private() is False
    
    def test_handle_different_points(self):
        """Should handle different points"""
        # Test with doubled generator point
        doubled_G = self.G.twice()
        pub_key = ECPublicKeyParameters(doubled_G, self.domain_params)
        
        assert pub_key.get_Q() is doubled_G
        assert pub_key.get_parameters().get_curve() is self.curve


class TestECPrivateKeyParameters:
    """Test ECPrivateKeyParameters class"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test fixtures"""
        self.domain_params = SM2.get_parameters()
        self.curve = self.domain_params.get_curve()
        self.G = self.domain_params.get_G()
        
        # Test key values
        self.test_private_key = 123456789
    
    def test_create_private_key_parameters_correctly(self):
        """Should create private key parameters correctly"""
        priv_key = ECPrivateKeyParameters(self.test_private_key, self.domain_params)
        
        assert priv_key.get_d() == self.test_private_key
        assert priv_key.get_parameters() is self.domain_params
        assert priv_key.is_private() is True
    
    def test_handle_zero_private_key(self):
        """Should handle zero private key"""
        priv_key = ECPrivateKeyParameters(0, self.domain_params)
        
        assert priv_key.get_d() == 0
        assert priv_key.is_private() is True
    
    def test_handle_large_private_key_values(self):
        """Should handle large private key values"""
        large_key = self.domain_params.get_n() - 1  # Maximum valid private key
        priv_key = ECPrivateKeyParameters(large_key, self.domain_params)
        
        assert priv_key.get_d() == large_key
        assert priv_key.is_private() is True
    
    def test_work_with_sm2_parameters(self):
        """Should work with SM2 parameters"""
        sm2_priv_key = 0x59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
        priv_key = ECPrivateKeyParameters(sm2_priv_key, self.domain_params)
        
        assert priv_key.get_d() == sm2_priv_key
        assert priv_key.get_parameters().get_n() == self.domain_params.get_n()


class TestKeyPairConsistency:
    """Test key pair consistency between public and private keys"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test fixtures"""
        self.domain_params = SM2.get_parameters()
        self.G = self.domain_params.get_G()
        self.test_private_key = 123456789
    
    def test_maintain_consistency_between_public_and_private_keys(self):
        """Should maintain consistency between public and private keys"""
        d = 0x59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
        Q = self.G.multiply(d)
        
        priv_key = ECPrivateKeyParameters(d, self.domain_params)
        pub_key = ECPublicKeyParameters(Q, self.domain_params)
        
        assert priv_key.get_d() == d
        assert pub_key.get_Q().equals(Q)
        assert priv_key.get_parameters() is pub_key.get_parameters()
    
    def test_verify_key_relationship(self):
        """Should verify key relationship"""
        priv_key = ECPrivateKeyParameters(self.test_private_key, self.domain_params)
        expected_public_point = self.G.multiply(self.test_private_key)
        pub_key = ECPublicKeyParameters(expected_public_point, self.domain_params)
        
        # Both keys should use the same domain parameters
        assert priv_key.get_parameters() is pub_key.get_parameters()
        
        # Public key should be derived from private key
        assert pub_key.get_Q().equals(self.G.multiply(priv_key.get_d()))


class TestParameterInheritance:
    """Test parameter inheritance from AsymmetricKeyParameter"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test fixtures"""
        self.domain_params = SM2.get_parameters()
        self.curve = self.domain_params.get_curve()
        self.G = self.domain_params.get_G()
        self.test_private_key = 123456789
        self.test_public_point = self.G.multiply(self.test_private_key)
    
    def test_properly_inherit_from_asymmetric_key_parameter(self):
        """Should properly inherit from AsymmetricKeyParameter"""
        pub_key = ECPublicKeyParameters(self.test_public_point, self.domain_params)
        priv_key = ECPrivateKeyParameters(self.test_private_key, self.domain_params)
        
        assert pub_key.is_private() is False
        assert priv_key.is_private() is True
    
    def test_provide_access_to_domain_parameters(self):
        """Should provide access to domain parameters"""
        pub_key = ECPublicKeyParameters(self.test_public_point, self.domain_params)
        priv_key = ECPrivateKeyParameters(self.test_private_key, self.domain_params)
        
        assert pub_key.get_parameters() is self.domain_params
        assert priv_key.get_parameters() is self.domain_params
        assert pub_key.get_parameters().get_curve() is self.curve
        assert priv_key.get_parameters().get_curve() is self.curve
