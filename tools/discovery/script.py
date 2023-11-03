import nmap

def check_host_alive(target_ip):
    try:
        scanner = nmap.PortScanner()
        return scanner.scan(target_ip, arguments='-sn')['scan'][target_ip]['status']['state']  # noqa: E501
    except Exception as identifier:
        print("exception host alive")
        print(identifier)
        print(type(identifier))
        return  None

def detect_os(target_ip):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target_ip, arguments='-O')
        return scanner[target_ip]['osmatch']
    except Exception as identifier:
        print("exception detect os")
        print(identifier)
        return None
    

def get_running_services(target_ip):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target_ip, arguments='-p 1-65535')
        return scanner[target_ip]['tcp']
    except Exception as identifier:
        print("exception running services")
        print(identifier)
        return  None
    

def get_open_ports(target_ip):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target_ip, arguments='-p 1-65535')
        return list(scanner[target_ip]['tcp'].keys())
    except Exception as identifier:
        print("exception open ports")
        print(identifier)
        return  None
    

def get_service_versions(target_ip):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target_ip, arguments='-p 1-65535 -sV')
        return scanner[target_ip]['tcp']
    except Exception as identifier:
        print("exception service versions")
        print(identifier)
        return  None
    