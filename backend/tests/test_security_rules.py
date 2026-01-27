import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import security_rules

def test_hardcoded_secret():
    code = 'api_key = "1234567890abcdef"'
    issues = security_rules.run_security_rules(code)
    assert any(i['type'] == 'hardcoded_secret' for i in issues)

def test_sql_injection():
    code = 'cursor.execute("SELECT * FROM users WHERE name = " + user_input)'
    issues = security_rules.run_security_rules(code)
    assert any(i['type'] == 'sql_injection_risk' for i in issues)
