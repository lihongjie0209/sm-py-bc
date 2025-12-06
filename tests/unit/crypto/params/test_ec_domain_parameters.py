"""
Unit tests for ECDomainParameters
Aligned with sm-js-bc/test/unit/crypto/params/ECDomainParameters.test.ts
"""
import pytest
from sm_bc.crypto.params.ec_domain_parameters import ECDomainParameters
from sm_bc.crypto.SM2 import SM2


class TestECDomainParameters:
    """Test ECDomainParameters class"""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test fixtures"""
        # Use SM2 standard parameters for testing
        self.sm2_params = SM2.get_parameters()
        self.curve = self.sm2_params.get_curve()
        self.G = self.sm2_params.get_G()
        self.n = self.sm2_params.get_n()
        self.h = self.sm2_params.get_h()
    
    def test_create_domain_parameters_correctly(self):
        """Should create domain parameters correctly"""
        params = ECDomainParameters(self.curve, self.G, self.n, self.h)
        
        assert params.get_curve() is self.curve
        assert params.get_G() is self.G
        assert params.get_n() == self.n
        assert params.get_h() == self.h
        assert params.get_seed() is None
    
    def test_create_domain_parameters_with_default_h_value(self):
        """Should create domain parameters with default h value"""
        params = ECDomainParameters(self.curve, self.G, self.n)
        
        assert params.get_h() == 1
    
    def test_create_domain_parameters_with_seed(self):
        """Should create domain parameters with seed"""
        seed = bytes([1, 2, 3, 4, 5])
        params = ECDomainParameters(self.curve, self.G, self.n, self.h, seed)
        
        assert params.get_seed() == seed
    
    def test_equality_correctly(self):
        """Should test equality correctly"""
        params1 = ECDomainParameters(self.curve, self.G, self.n, self.h)
        params2 = ECDomainParameters(self.curve, self.G, self.n, self.h)
        params3 = ECDomainParameters(self.curve, self.G, self.n, 2)  # Different h
        
        assert params1.equals(params2) is True
        assert params1.equals(params3) is False
        assert params1.equals(None) is False
        assert params1.equals("not a parameters") is False
    
    def test_compute_hashcode_consistently(self):
        """Should compute hashCode consistently"""
        params1 = ECDomainParameters(self.curve, self.G, self.n, self.h)
        params2 = ECDomainParameters(self.curve, self.G, self.n, self.h)
        
        assert params1.hash_code() == params2.hash_code()
    
    def test_create_sm2_domain_parameters(self):
        """Should create SM2 domain parameters"""
        # SM2 standard curve parameters
        sm2_params = ECDomainParameters(self.curve, self.G, self.n, self.h)
        
        assert sm2_params.get_curve().get_field_size() == 256
        assert sm2_params.get_n() == self.n
        assert sm2_params.get_h() == 1
    
    def test_handle_large_parameter_values(self):
        """Should handle large parameter values"""
        large_n = 2 ** 256 - 1
        params = ECDomainParameters(self.curve, self.G, large_n, self.h)
        
        assert params.get_n() == large_n
    
    def test_provide_getters_for_all_parameters(self):
        """Should provide getters for all parameters"""
        params = self.sm2_params
        
        assert params.get_curve() is not None
        assert params.get_G() is not None
        assert isinstance(params.get_n(), int)
        assert isinstance(params.get_h(), int)
        assert params.get_h() == 1
