import coding_standards

def test_naming_convention():
    code = 'def BadFunctionName():'
    issues = coding_standards.run_coding_standards_rules(code)
    assert any(i['type'] == 'naming_convention' for i in issues)

def test_logging_practice():
    code = 'print("debug")'
    issues = coding_standards.run_coding_standards_rules(code)
    assert any(i['type'] == 'logging_practice' for i in issues)
