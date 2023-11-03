import os
import threading
import requests
import socket

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


def process_batch(subdomains, target_domain, discovered_subdomains):
    for index, subdomain in enumerate(subdomains):
        url_http = f"http://{subdomain}.{target_domain}"
        url_https = f"https://{subdomain}.{target_domain}"

        # print(index, " :: ", url_http)

        try:
            response_http_get = requests.get(url_http)
            response_http_post = requests.post(url_http)

            if response_http_get.status_code in [
                200,
                400,
                403,
                500,
                301,
                302,
                304,
                307,
                308,
                429,
                503,
            ] or response_http_post.status_code in [
                200,
                400,
                403,
                500,
                301,
                302,
                304,
                307,
                308,
                429,
                503,
            ]:  # noqa: E501
                resolved_ip = get_ip_from_domain(url_http)
                discovered_subdomains["http"].append(
                    {"url": url_http, "resolved_ip": resolved_ip}
                )  # noqa: E501
        except requests.ConnectionError:
            # if the subdomain does not exist, just pass, print nothing
            print("connection error http ", index, " ", url_http)
            # print(response.url)
            # pass
        except Exception as e:
            print("not connection error http")
            print(type(e))

        try:
            response_https_get = requests.get(url_https)
            response_https_post = requests.post(url_https)

            if response_https_get.status_code in [
                200,
                400,
                403,
                500,
                301,
                302,
                304,
                307,
                308,
                429,
                503,
            ] or response_https_post.status_code in [
                200,
                400,
                403,
                500,
                301,
                302,
                304,
                307,
                308,
                429,
                503,
            ]:  # noqa: E501
                resolved_ip = get_ip_from_domain(url_http)
                discovered_subdomains["https"].append(
                    {"url": url_https, "resolved_ip": resolved_ip}
                )  # noqa: E501
        except requests.ConnectionError:
            # if the subdomain does not exist, just pass, print nothing
            print("connection error https ", index, " ", url_https)
            # print(response.url)
            # pass
        except Exception as e:
            print("not connection error https")
            print(type(e))


def process_subdomains_in_batches(subdomains, target_domain, batch_size):
    batches = [
        subdomains[i : i + batch_size] for i in range(0, len(subdomains), batch_size)
    ]  # noqa: E501
    discovered_subdomains = {"http": [], "https": []}
    threads = []

    def process_batch_wrapper(batch):
        process_batch(batch, target_domain, discovered_subdomains)

    for batch in batches:
        thread = threading.Thread(target=process_batch_wrapper, args=(batch,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return discovered_subdomains


def subdomain_analyzer(target_domain):
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))

        txt_file_path = os.path.join(script_dir, "subdomains.txt")
        # read possible subdomain file
        file = open(txt_file_path, "r")

        # save the file content
        content = file.read()

        # split to get individual subdomain possibility
        subdomains = content.splitlines()

        # a list of discovered subdomains
        discovered_subdomains = {"http": [], "https": []}

        batch_size = 2000

        discovered_subdomains = process_subdomains_in_batches(
            subdomains, target_domain, batch_size
        )  # noqa: E501
        # return the dict()
        return discovered_subdomains
        # pass
    except Exception as identifier:
        print("ran into exception in subdomain ", identifier)
        return None
