import json
import os
import shutil
import socket
import ssl
import datetime

import whois
import threading
import subprocess
import re


from tools.malware_url.malware_urls import get_malware_url_source
from tools.subdomain.script import subdomain_analyzer

from tools.webcrawler.webcrawler import crawl_url

from tools.discovery.script import (
    check_host_alive,
    detect_os,
    get_open_ports,
    get_running_services,
    get_service_versions,
)  # noqa: E501

def identify_input(input_string):
    # Regular expressions to match URLs and IPs
    url_pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    
    if re.match(url_pattern, input_string):
        print("It's a URL.")
        return "uri"
    
    elif re.match(ip_pattern, input_string):
        print("It's an IP address.")
        return "ip"
    
    elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_string):
        print("It's a domain.")
        return "domain"
    
    else:
        print("It's some random string.")
        return None

        
domains_url = [
    "devnote.in",
    "devnote_wrong.in",
    "stackoverflow.com",
    "stackoverflow.com/status/404",
    "google.com",
    "cdac.in",
]


def make_all_reports_accessible():
    """
    The function `make_all_reports_accessible()` sets the permissions of all files and directories in
    the "reports" directory to be accessible by all users.
    """  # noqa: E501
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        reports_dir = os.path.join(script_dir, "reports")

        os.system(f"sudo chmod -R 777 {reports_dir}")
    except Exception as identifier:
        print(identifier)
        pass


def get_ip_from_domain(target):
    """
    The function `get_ip_from_domain` takes a target (either an IP address or a domain name) as input
    and returns the corresponding IP address.

    :param target: The "target" parameter in the "get_ip_from_domain" function is the domain name or IP
    address that you want to resolve to an IP address
    :return: The function `get_ip_from_domain` returns the IP address of the given domain name or None
    if an error occurs.
    """  # noqa: E501
    try:
        # Check if the input is an IP address
        socket.inet_pton(socket.AF_INET, target)
        return target
    except socket.error:
        try:
            # Attempt to resolve domain to IP
            ip = socket.gethostbyname(target)
            return ip
        except socket.error as e:
            print(f"Error: {e}")
            return None


def get_report_path(scan_type, report_type):
    """
    The function `get_report_path` returns the path to a specific report type for a given scan type.

    :param scan_type: The `scan_type` parameter is a string that represents the type of scan being
    performed. It could be something like "vulnerability_scan" or "malware_scan"
    :param report_type: The `report_type` parameter is a string that represents the type of report you
    want to generate. It could be something like "summary", "detailed", "csv", etc
    :return: the path to the directory where the specified report type is stored.
    """  # noqa: E501
    script_dir = os.path.dirname(os.path.abspath(__file__))
    reports_common_dir = os.path.join(script_dir, "reports")
    scan_type_path = os.path.join(reports_common_dir, scan_type)
    report_type_dir = os.path.join(scan_type_path, report_type)
    return report_type_dir


def check_report_exists(scan_type, report_type, hostname):
    """
    The function `check_report_exists` checks if a report exists for a given scan type, report type, and
    hostname.

    :param scan_type: The scan_type parameter represents the type of scan being performed. It could be a
    vulnerability scan, a network scan, or any other type of scan
    :param report_type: The `report_type` parameter is a string that specifies the type of report. It
    could be something like "summary", "detailed", or "full"
    :param hostname: The `hostname` parameter represents the name of the host for which the report is
    being checked
    :return: The function `check_report_exists` returns either `False` if no report files are found for
    the given `scan_type`, `report_type`, and `hostname`, or it returns a list of report files if they
    exist.
    """  # noqa: E501
    try:
        report_dir = get_report_path(scan_type, report_type)

        report_files = [
            f
            for f in os.listdir(report_dir)
            if f.startswith(hostname + "_") and f.endswith(".json")
        ]  # noqa: E501

        if len(report_files) == 0:
            return False
        else:
            return report_files

    except Exception as e:
        print(e)
        print(os.listdir(report_dir))
        return []


def get_most_recent_report(report_files):
    today = datetime.datetime.now()

    # Initialize variables to keep track of the most recent file and its timestamp
    most_recent_file = None
    most_recent_timestamp = None

    for file in report_files:
        parts = file.split("_")

        if len(parts) > 6 and parts[-1].endswith(".json"):
            parts[-1] = parts[-1].split(".json")[0].strip()
            try:
                timestamp = datetime.datetime.strptime(
                    "_".join(parts[-6:]), "%Y_%m_%d_%H_%M_%S"
                )
                print("here 2 ", timestamp)
                if today - timestamp < datetime.timedelta(days=5):
                    if (
                        most_recent_timestamp is None
                        or timestamp > most_recent_timestamp
                    ):  # noqa: E501
                        most_recent_file = file
                        most_recent_timestamp = timestamp
            except ValueError:
                pass  # Skip files with incorrect timestamp format
            except Exception as e:  # noqa: F841
                print("exception")
                pass

    return most_recent_file


def is_scan_necessary(scan_type, report_type, hostname):
    try:
        report_file_dir = get_report_path(scan_type, report_type)
        report_files = check_report_exists(scan_type, report_type, hostname)

        usable_report = get_most_recent_report(report_files)
        print('usable report is scan necessary')
        print(usable_report)

        if usable_report is None:
            return False
        else:
            return os.path.join(report_file_dir, usable_report)

    except Exception as e:  # noqa: F841
        return False


def load_json_file(report_file_path):
    jsonFile = None

    try:
        with open(report_file_path, "r") as f:
            jsonFile = json.load(f)
        return jsonFile
    except Exception as identifier:
        print(identifier)
        return jsonFile


def get_ssl_info(hostname):
    """
    The `get_ssl_info` function retrieves SSL certificate information for a given
    hostname and returns it in a formatted dictionary. It also incorporates persistent storage by saving
    and retrieving information from a report file.

    :param hostname: The `hostname` parameter is a string that represents the hostname or IP address of
    the server for which you want to retrieve SSL information
    :return: The function returns a dictionary containing information about the SSL certificate for the
    given hostname. The dictionary includes details such as the expiry date, issue date, issuer, subject,
    and other relevant information about the SSL certificate.
    """  # noqa: E501
    # Define the report file path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    report_dir = os.path.join(script_dir, "reports/domain/ssl")
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y_%m_%d_%H_%M_%S")
    report_filename = f"{hostname}_{timestamp}.json"
    report_path = os.path.join(report_dir, report_filename)

    context = ssl.create_default_context()
    context.check_hostname = False

    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=hostname,
    )
    conn.settimeout(5.0)

    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()

    formatted_ssl_info = dict()

    expiry = datetime.datetime.strptime(ssl_info["notAfter"], r"%b %d %H:%M:%S %Y %Z")

    for key, value in ssl_info.items():
        if isinstance(value, datetime.datetime):
            new_key = ""
            if key == "notAfter":
                new_key = "Expiry Date"
            elif key == "notBefore":
                new_key = "Issue Date"
            else:
                new_key = key
            formatted_ssl_info[new_key] = value.strftime("%Y-%m-%d %H:%M:%S")
        else:
            try:
                if key == "subject":
                    for element in ssl_info["subject"]:
                        formatted_ssl_info[element[0][0]] = element[0][1]
                elif key == "issuer":
                    formatted_ssl_info["issuer"] = dict()
                    for item in ssl_info["issuer"]:
                        formatted_ssl_info["issuer"][item[0][0]] = item[0][1]
                else:
                    formatted_ssl_info[key] = value
            except Exception as exception:
                print(exception)
                formatted_ssl_info[key] = value

    diff = expiry - now

    formatted_ssl_info["Expiry Day"] = diff.days

    # Save the formatted SSL info to the report file
    with open(report_path, "w") as file:
        json.dump(formatted_ssl_info, file, indent=4, sort_keys=True)

    make_all_reports_accessible()

    return formatted_ssl_info


def get_subdomain_info(hostname):
    """
    The function `get_subdomain_info` takes a hostname as input, checks if a report file exists and is
    less than 10 days old, and runs a Python script to perform subdomain lookup using the Knockpy tool.

    :param hostname: The `hostname` parameter is a string that represents the domain name for which you
    want to retrieve subdomain information
    :return: either "success" or "failed" depending on the outcome of the subdomain lookup process.
    """  # noqa: E501
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))

        # Define the report file path
        report_dir = os.path.join(script_dir, "reports/domain/subdomain")

        discovered_subdomains = subdomain_analyzer(hostname)

        if discovered_subdomains is not None:
            # create report file name
            now = datetime.datetime.now()
            timestamp = now.strftime("%Y_%m_%d_%H_%M_%S")
            json_filename = f"{hostname}_{timestamp}.json"

            file_path = os.path.join(report_dir, json_filename)

            with open(file_path, "w") as f:
                json.dump(discovered_subdomains, f)

            return discovered_subdomains
            # pass
        else:
            return None

        return "success"
    except Exception as e:
        print(e)
        return None


def get_whois_info(hostname):
    """
    The `get_whois_info` function retrieves WHOIS information for a given hostname, saves it to a JSON
    file, and returns the extracted information.

    :param hostname: The `hostname` parameter is a string that represents the domain name or IP address
    for which you want to retrieve the WHOIS information
    :return: The function `get_whois_info` returns the required WHOIS information for a given hostname.
    If a valid JSON file containing the information exists and is less than 10 days old, it is loaded
    and returned. Otherwise, the function uses the `whois` command to retrieve the WHOIS information,
    extracts the required information, saves it to a JSON file, and returns it. If any
    """  # noqa: E501
    try:
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y_%m_%d_%H_%M_%S")
        json_filename = f"{hostname}_{timestamp}.json"

        script_dir = os.path.dirname(os.path.abspath(__file__))
        report_dir = os.path.join(script_dir, "reports/domain/whois")

        report_filename = os.path.join(report_dir, json_filename)

        info = whois.whois(hostname)

        required_info = dict()

        # print(type(info))

        if info is not None:
            # y = info.items()
            for key, value in info.items():
                print(key, " :: ", type(value))

                if isinstance(value, datetime.datetime):
                    required_info[key] = str(value)
                elif isinstance(value, list):
                    nl = []
                    for item in value:
                        if item is not None and isinstance(item, datetime.datetime):
                            nl.append(str(item))
                        else:
                            nl.append(item)
                    required_info[key] = nl
                else:
                    required_info[key] = value

        else:
            pass

        # print(required_info)

        # Save the whois_info to a JSON file
        with open(report_filename, "w") as file:
            json.dump(required_info, file)

        make_all_reports_accessible()

        return required_info

    except FileNotFoundError as e:
        return f"Error: {e}. Please make sure 'whois' command is available in your system."  # noqa: E501
    except PermissionError as e:
        return f"Error: {e}. Permission denied while trying to run 'whois' command."
    except Exception as e:
        return str(e)


def webcrawl_helper(uri):
    try:
        result = crawl_url(uri)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        report_dir = os.path.join(script_dir, "reports/domain/webcrawl")
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y_%m_%d_%H_%M_%S")
        report_filename = f"{uri}_{timestamp}.json"
        report_path = os.path.join(report_dir, report_filename)

        with open(report_path, "w") as f:
            json.dump(result, f)

        return result
    except Exception as identifier:
        print(identifier)
        return None


def is_malware_source(hostname):
    try:
        trie = get_malware_url_source()
        # print(data)
        if trie.search(hostname):
            return True
        else:
            return False
    except Exception as identifier:
        print(identifier)
        return None


def run_nmap_discover(scan_type, report_type, hostname):
    try:
        resolved_ip = get_ip_from_domain(hostname)
        print(resolved_ip)

        if resolved_ip is not None:
            # Define a shared dictionary to store results
            results = {}

            # Define functions for concurrent execution
            def check_host_alive_thread():
                results["host_alive"] = check_host_alive(resolved_ip)
                print("1")
                # print(results['host_alive'])

            def detect_os_thread():
                results["detected_os"] = detect_os(resolved_ip)
                print("2")
                # print(results['detected_os'])

            def get_open_ports_thread():
                results["open_ports"] = get_open_ports(resolved_ip)
                print("3")
                # print(results['open_ports'])

            def get_running_services_thread():
                results["active_services"] = get_running_services(resolved_ip)
                print("4")
                # print(results["active_services"])

            def service_versions_thread():
                results["service_versions"] = get_service_versions(resolved_ip)
                print("5")
                # print(results["service_versions"])

            # Create threads for each function
            threads = [
                threading.Thread(target=check_host_alive_thread),
                threading.Thread(target=detect_os_thread),
                threading.Thread(target=get_open_ports_thread),
                threading.Thread(target=get_running_services_thread),
                threading.Thread(target=service_versions_thread),
            ]

            # Start the threads
            for thread in threads:
                thread.start()

            # Wait for all threads to finish
            for thread in threads:
                thread.join()

            information = {
                "host_status": results["host_alive"],
                "open_ports": results["open_ports"],
                "active_services": results["active_services"],
                "detected_os": results["detected_os"],
                "service_versions": results["service_versions"],
            }

            script_dir = os.path.dirname(os.path.abspath(__file__))
            report_dir = os.path.join(script_dir, "reports/domain/discovery")

            # get directory where report needs to be saved
            now = datetime.datetime.now()
            timestamp = now.strftime("%Y_%m_%d_%H_%M_%S")
            json_filename = f"{hostname}_{timestamp}.json"

            # now join these two

            report_file_path = os.path.join(report_dir, json_filename)

            with open(report_file_path, "w") as f:
                json.dump(information, f)

            return information
        else:
            return "could not resolve the IP address"

    except Exception as identifier:
        print(identifier)
        return None


def subdomain_knock_analyzer(target_domain):
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        knockpy_tool_path = os.path.join(script_dir, "tools/subdomain/knockpy.py")

        python_script_path = shutil.which("python")
        report_dir = os.path.join(script_dir, "reports/domain/subdomain")

        print(script_dir)
        print(knockpy_tool_path)
        print(python_script_path)

        command_string = f"{python_script_path} {knockpy_tool_path} {target_domain} -o {report_dir}"  # noqa: E501

        # process = subprocess.check_output(command_string, text=True, shell=)
        print(command_string)

        process = subprocess.Popen(
            command_string,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )  # noqa: E501
        print("command is run")
        # Check if the subprocess is still running
        while True:
            subprocess_return_code = process.poll()
            if subprocess_return_code is not None:
                break

            # The subprocess is still running, so return a response to the user indicating that the subdomain discovery process has been initiated  # noqa: E501
            print(
                "subprocess is still running. Return PID so that it can be tracked later"  # noqa: E501
            )  # noqa: E501
            return {
                "message": "'Sub Domain Discovery has been initiated. Please check back later for the results",  # noqa: E501
                'status': 'still undergoing',
                "process_id": process.pid
            }
        
        print('subprocess has completed. Return status')

        if subprocess_return_code == 0:
            return {
                "message": "Scan completed successfully",
                "status": "success"
            }
        else:
            return {
                "status": "failed",
                "message": "Sub domain discovery failed",
            }

        # The subprocess has finished running, so return the subprocess return code
        return subprocess_return_code

    except Exception as identifier:
        print("ran into exception in subdomain ", identifier)
        return None
