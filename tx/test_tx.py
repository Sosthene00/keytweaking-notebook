import pytest

from tx.tx import *
from tx.script import *

@pytest.fixture
def message():
    m = "Ceci est un message test"
    return m

@pytest.fixture
def scriptpubkey():
    scripts = []
    with open('pubkey', 'r') as file:
        pubkeys = [line.strip() for line in file]
    for pubkey in pubkeys:
        scripts.append(Script([bytes.fromhex(pubkey), 0xac]))
    return scripts

@pytest.fixture
def scriptsig():
    scripts = []
    with open('sigs', 'r') as file:
        sigs = [line.strip() for line in file]
    for sig in sigs:
        scripts.append(Script([bytes.fromhex(sig)]))
    return scripts

def test_p2pk(scriptpubkey, scriptsig, message):
    m = message
    combined_script = scriptsig[0] + scriptpubkey[0]
    assert combined_script.evaluate(m) 
