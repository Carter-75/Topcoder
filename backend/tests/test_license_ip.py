import license_ip

def test_license_detection():
    code = '/*\nMIT License\n*/'
    issues = license_ip.run_license_ip_checks(code)
    assert any(i['type'] == 'license_detected' for i in issues)

def test_ip_duplication():
    code = 'long line of code that is repeated\nlong line of code that is repeated'
    issues = license_ip.run_license_ip_checks(code)
    assert any(i['type'] == 'ip_duplication' for i in issues)
