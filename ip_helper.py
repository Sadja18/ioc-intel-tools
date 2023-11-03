import datetime
import ssl
import threading
import mongoengine
import requests
from requests.exceptions import SSLError
from requests.exceptions import MissingSchema
from requests.exceptions import InvalidSchema
import json

from blacklisted_ip_trie_create import clone_and_process_git_repo

from report_models import get_ip_collection_class, save_ip_report_to_collection
from tools.discovery.script import (
    check_host_alive,
    detect_os,
    get_running_services,
    get_service_versions,
    get_open_ports,
)


def is_ip_report_exists(report_type, ip_address, sub_key_check=False, sub_key=""):
    """
    The function `is_ip_report_exists` checks if a report of a given type exists for a specific IP
    address, and returns the status or data accordingly.

    :param report_type: The `report_type` parameter is a string that represents the type of report you
    want to check for. It is used to determine the collection name where the report is stored
    :param ip_address: The `ip_address` parameter is the IP address for which you want to check if a
    report exists
    :param sub_key_check: The `sub_key_check` parameter is a boolean flag that determines whether to
    check for the existence of a specific sub-key in the `information` field of the existing object. If
    `sub_key_check` is `True`, then the function will check if the `sub_key` is present in the, defaults
    to False (optional)
    :param sub_key: The `sub_key` parameter is an optional parameter that is used to check if a specific
    sub-key exists in the `information` field of the existing object. If `sub_key_check` is set to
    `True` and `sub_key` is provided, the function will return `{"status":
    :return: a dictionary with different keys and values depending on the conditions met. The possible
    keys and their corresponding values are:
    """
    try:
        collection_name = get_ip_collection_class(report_type)

        if collection_name is not None:
            # check if report exists
            try:
                existing_object = collection_name.objects.get(ipAddress=ip_address)
                print("document exists")

                five_days_ago = datetime.datetime.now() - datetime.timedelta(days=5)

                print("checking if it is recent enough")
                last_updated = existing_object.updatedAt

                if sub_key_check:
                    print(sub_key not in existing_object.information)

                if last_updated <= five_days_ago or (
                    sub_key_check and sub_key not in existing_object.information
                ):
                    return {"status": "rescan"}
                else:
                    return {"data": existing_object.information}
            except mongoengine.DoesNotExist as error:
                print(f"document for {ip_address} does not exists")
                print(error)
                return {"status": "not exists"}
        else:
            return {"status": "no report of this type exists"}
    except Exception as identifier:
        print("exception is checking if ip report exists")
        print(identifier)
        return None


def get_ip_whois_info(ip_address):
    """
    The function `get_ip_whois_info` retrieves WHOIS information for a given IP address and saves it to
    a collection.

    :param ip_address: The `ip_address` parameter is a string that represents the IP address for which
    you want to retrieve WHOIS information
    :return: a dictionary with the key "information" and the value being the information obtained from
    the WHOIS lookup for the given IP address. If the WHOIS lookup is unsuccessful or encounters an
    error, it will return a dictionary with the key "data" and the value being None.
    """
    try:
        base_uri = "https://rdap.apnic.net/ip/"

        end_uri = base_uri + ip_address

        response = requests.get(end_uri)

        if response.status_code == 200:
            data = response.content.decode("utf-8")

            information = json.loads(data)

            # print(type(data))
            print(type(information))
            # print(information)

            # attempt to save to collection
            result = save_ip_report_to_collection("whois", ip_address, information)

            print(result)
            return {"information": information}
        else:
            return {"data": None}
    except Exception as identifier:
        print(identifier)
        print("exception")
        return None


def check_if_ip_is_blacklisted(ip_address):
    """
    The function `check_if_ip_is_blacklisted` checks if an IP address is blacklisted using a trie data
    structure and saves the result to a collection.

    :param ip_address: The `ip_address` parameter is a string that represents an IP address that you
    want to check if it is blacklisted
    :return: The function `check_if_ip_is_blacklisted` returns a dictionary with the key
    "ipsum_blacklisted" and its corresponding value. If the IP address is blacklisted, the value will be
    the blacklisted result. If the IP address is not blacklisted, the value will be None.
    """
    try:
        # update the ipsum.txt
        trie_root = clone_and_process_git_repo()

        blacklisted_result = trie_root.search(ip_address)

        if blacklisted_result is not None:
            result = save_ip_report_to_collection(
                "host_info", ip_address, {"ipsum_blacklisted": blacklisted_result}, True
            )
            print(result)

            return {"ipsum_blacklisted": blacklisted_result}
        else:
            return {"ipsum_blacklisted": None}
    except Exception as identifier:
        print("exception in check if IP is blacklisted")
        print(identifier)
        return None


def ip_host_alive(ip_address):
    """
    The `ip_host_alive` function checks if a given IP address is alive by running a concurrent thread to
    check the host's status and save the result to a collection.

    :param ip_address: The `ip_address` parameter is the IP address of the host that you want to check
    if it is alive or not
    :return: a dictionary containing the host status information.
    """
    try:
        if ip_address is not None:
            # Define a shared dictionary to store results
            results = {}
            print("ip_address in check host alive")

            # Define functions for concurrent execution
            def check_host_alive_thread():
                results["host_alive"] = check_host_alive(ip_address)
                print("results")
                result = save_ip_report_to_collection(
                    "host_info",
                    ip_address,
                    {"host_status": results["host_alive"]},
                    True,
                )
                print("1")
                print(result)

            # Create threads for each function
            threads = [threading.Thread(target=check_host_alive_thread)]

            # Start the threads
            for thread in threads:
                thread.start()

            # Wait for all threads to finish
            for thread in threads:
                thread.join()

            information = {
                "host_status": results["host_alive"],
            }

            return information
        else:
            return "could not resolve the IP address"

    except Exception as identifier:
        print(identifier)
        return None


def ip_detect_os(ip_address):
    """
    The `ip_detect_os` function takes an IP address as input, checks if the IP address is not None,
    creates a thread to detect the operating system of the IP address, saves the detected OS to a
    collection, and returns the detected OS information.

    :param ip_address: The `ip_address` parameter is the IP address that you want to detect the
    operating system for
    :return: a dictionary containing the detected operating system information of the given IP address.
    If the IP address is None, it returns the string "could not resolve the IP address". If an exception
    occurs, it returns None.
    """
    try:
        if ip_address is not None:
            # Define a shared dictionary to store results
            results = {}
            print("ip_address in check host alive")

            # Define functions for concurrent execution
            def check_host_alive_thread():
                results["os"] = detect_os(ip_address)
                print("results")
                result = save_ip_report_to_collection(
                    "host_info", ip_address, {"detected_os": results["os"]}, True
                )
                print("1")
                print(result)

            # Create threads for each function
            threads = [threading.Thread(target=check_host_alive_thread)]

            # Start the threads
            for thread in threads:
                thread.start()

            # Wait for all threads to finish
            for thread in threads:
                thread.join()

            information = {
                "detected_os": results["os"],
            }

            return information
        else:
            return "could not resolve the IP address"

    except Exception as identifier:
        print(identifier)
        return None


def ip_port_scan(ip_address):
    """
    The `ip_port_scan` function initiates a port scan on a given IP address and returns a response
    indicating that the scan has been initiated.

    :param ip_address: The `ip_address` parameter is the IP address that you want to perform a port scan
    on
    :return: a response dictionary containing a message indicating that the port scan has been initiated
    and the results will be available later. It also includes the thread's identification number (ident)
    and native ID.
    """
    try:
        if ip_address is not None:
            results = {}

            def get_open_ports_thread():
                # Your port scanning code here

                # Store the results in the 'results' dictionary
                results["open_ports"] = get_open_ports(ip_address)

                # Save the results to the database
                result = save_ip_report_to_collection(
                    "open_ports", ip_address, {"open_ports": results["open_ports"]}
                )
                print("3")
                print(result)

            # Create a thread for the port scan
            scan_thread = threading.Thread(target=get_open_ports_thread)

            # Start the thread
            scan_thread.start()

            # Return an acknowledgment to the client along with the thread's PID
            response = {
                "message": "Port scan has been initiated. Results will be available later.",
                "thread_ident": scan_thread.ident,
                "thread_native_id": scan_thread.native_id,
            }
            return response

    except Exception as e:
        # Handle exceptions here
        print({"error": str(e)})
        return None


def ip_active_services(ip_address):
    """
    The function `ip_active_services` initiates a thread to scan for active services on a given IP
    address and returns a response acknowledging the initiation of the scan.

    :param ip_address: The `ip_address` parameter is the IP address of the target machine for which you
    want to scan for active services
    :return: a response dictionary that includes a message indicating that the active services scan has
    been initiated, along with the thread's identification and native ID.
    """
    try:
        if ip_address is not None:
            results = {}

            def get_running_services_thread():
                results["active_services"] = get_running_services(ip_address)
                print("4")

                result = save_ip_report_to_collection(
                    "active_services",
                    ip_address,
                    {"active_services": results["active_services"]},
                )
                print(result)

            # Create a thread for the port scan
            scan_thread = threading.Thread(target=get_running_services_thread)

            # Start the thread
            scan_thread.start()

            # Return an acknowledgment to the client along with the thread's PID
            response = {
                "message": "Active Services scan has been initiated. Results will be available later.",
                "thread_ident": scan_thread.ident,
                "thread_native_id": scan_thread.native_id,
            }
            return response

    except Exception as e:
        # Handle exceptions here
        print({"error": str(e)})
        return None


# def ip_nmap_discover(scan_type, report_type, ip_address):
#     try:
#         if ip_address is not None:
#             # Define a shared dictionary to store results
#             results = {}

#             # Define functions for concurrent execution
#             def check_host_alive_thread():
#                 results["host_alive"] = check_host_alive(ip_address)

#                 result = save_ip_report_to_collection(
#                     "host_info",
#                     ip_address,
#                     {"host_status": results["host_alive"]},
#                     True,
#                 )
#                 print("1")
#                 print(result)

#             def detect_os_thread():
#                 results["detected_os"] = detect_os(ip_address)
#                 result = save_ip_report_to_collection(
#                     "host_info",
#                     ip_address,
#                     {"detected_os": results["detected_os"]},
#                     True,
#                 )

#                 print("2")
#                 print(result)

#             def get_open_ports_thread():
#                 results["open_ports"] = get_open_ports(ip_address)
#                 print("3")
#                 # print(results['open_ports'])

#             def get_running_services_thread():
#                 results["active_services"] = get_running_services(ip_address)
#                 print("4")
#                 # print(results["active_services"])

#             def service_versions_thread():
#                 results["service_versions"] = get_service_versions(ip_address)
#                 print("5")
#                 # print(results["service_versions"])

#             # Create threads for each function
#             threads = [
#                 threading.Thread(target=check_host_alive_thread),
#                 threading.Thread(target=detect_os_thread),
#                 threading.Thread(target=get_open_ports_thread),
#                 threading.Thread(target=get_running_services_thread),
#                 threading.Thread(target=service_versions_thread),
#             ]

#             # Start the threads
#             for thread in threads:
#                 thread.start()

#             # Wait for all threads to finish
#             for thread in threads:
#                 thread.join()

#             information = {
#                 "host_status": results["host_alive"],
#                 "open_ports": results["open_ports"],
#                 "active_services": results["active_services"],
#                 "detected_os": results["detected_os"],
#                 "service_versions": results["service_versions"],
#             }

#             return information
#         else:
#             return "could not resolve the IP address"

#     except Exception as identifier:
#         print(identifier)
#         return None


def ip_api(ip_address):
    """
    The `ip_api` function takes an IP address as input and makes a request to the ip-api.com API to
    retrieve information about the IP address, such as its country, region, city, latitude, longitude,
    ISP, and more.

    :param ip_address: The `ip_address` parameter is the IP address for which you want to retrieve
    information. This function uses the IP-API service to get details about the provided IP address
    :return: The function `ip_api(ip_address)` is returning a JSON object containing information about
    the given IP address.
    """
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"
        )

        content = response.content.decode("utf-8")

        # print(content)
        print(type(content))

        json_parsed = json.loads(content)

        return json_parsed
        pass
    except Exception as identifier:
        print(identifier)
        return None


def get_response_info(ip_address, ports, user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"):
    """
    Gets the response headers, cookies, content, and URL for a given IP address and port list.

    Args:
        ip_address: The IP address of the server.
        ports: A list of ports to try.
        user_agent: The user agent to use in the HTTP requests.

    Returns:
        A dictionary containing the following keys:
        "headers": The response headers.
        "cookies": The response cookies.
        "content": The response content, decoded as UTF-8.
        "url": The URL of the response.
    """

    # Handle exceptions
    try:  
        results = dict()

        # Try each port
        for port in ports:
            try:
                uri = f"http://{ip_address}:{port}"

                if port == 443:
                    uri = f"https://{ip_address}"
                elif port == 80:
                    uri = f"http://{ip_address}"
                else:
                    uri = f"http://{ip_address}:{port}"
                # Make an HTTP request to the IP address and port
                response = requests.get(uri, headers={"User-Agent": user_agent})

                # Return the response info if the request was successful
                results[str(port)] = {
                "headers": response.headers,
                "cookies": response.cookies,
                "content": response.content.decode("utf-8"),
                "url": response.url,
                }
            except SSLError as sslError:
                # Handle SSL errors
                results[str(port)] = str(sslError)
                # pass
            except MissingSchema as missingSchemaError:
                results[str(port)] = str(missingSchemaError)
                # Handle missing schema errors
                # pass
            except InvalidSchema as invalidSchemaError:
                results[str(port)] = invalidSchemaError
                # Handle invalid schema errors
                # pass
            except Exception as exception:
                results[str(port)] = exception

        return results
        # Raise an exception if none of the ports were successful
        raise Exception("Failed to connect to any of the given ports")
    except Exception as e:
        print(e)
        # Return None if an exception occurred
        return None
        


def open_port_request_qualifier(ip_address):
    try:
        # get collection name
        open_ports_collection_name = get_ip_collection_class("open_ports")
        port_request_collection_name = get_ip_collection_class("port_request")

        try:
            # check if open port scan is complete for given ip
            existing_object = open_ports_collection_name.objects.get(
                ipAddress=ip_address
            )

            if (
                "information" in existing_object
                and "open_ports" in existing_object["information"]
                and isinstance(existing_object["information"]["open_ports"], list)
            ):
                if len(existing_object['information']['open_ports']) > 0:
                    ports = existing_object['information']['open_ports']
                    results = get_response_info(ip_address=ip_address, ports=ports)

                    print(results)
                    return results
                else:
                    return {'status': 'no open ports'}
            else:
                return {"status": "scan is needed to be run again"}

        except mongoengine.DoesNotExist as error:
            print("error")
            print(error)
            return {"status": "no open port scan report"}
        
        except Exception as e:
            print("error ", e)
            return None

        pass
    except Exception as identifier:
        print("open port request test bench error")
        print(identifier)
        return None
