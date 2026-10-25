import pytest
from security.pseudonym_manager import PseudonymManager

def test_pseudonym_generation_format():
    pm = PseudonymManager()
    pseudo = pm.generate_pseudonym()
    
    assert isinstance(pseudo, str)
    assert pseudo.startswith("p6g-ps-")
    # Base64url token of 16 bytes is 22 characters + 7 chars prefix = 29 chars minimum
    assert len(pseudo) >= 28

def test_pseudonym_uniqueness_sample():
    """Verify uniqueness across 5,000 generated pseudonyms (collision resistance)."""
    pm = PseudonymManager()
    sample_size = 5000
    generated = set()

    for _ in range(sample_size):
        pseudo = pm.generate_pseudonym()
        assert pseudo not in generated, f"Collision detected for pseudonym: {pseudo}"
        generated.add(pseudo)

    assert len(generated) == sample_size
