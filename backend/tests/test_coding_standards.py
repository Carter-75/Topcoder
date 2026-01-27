import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import coding_standards

def test_naming_convention():
    code = 'def BadFunctionName():'
    issues = coding_standards.run_coding_standards_rules(code)
    assert any(i['type'] == 'naming_convention' for i in issues)

def test_logging_practice():
    code = 'print("debug")'
    issues = coding_standards.run_coding_standards_rules(code)
    assert any(i['type'] == 'logging_practice' for i in issues)
