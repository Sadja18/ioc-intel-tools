from flask import Blueprint, make_response, request, jsonify
from flask_cors import cross_origin
from ip_helper import (
    check_if_ip_is_blacklisted,
    get_ip_whois_info,
    ip_active_services,
    ip_api,
    ip_detect_os,
    ip_host_alive,
    ip_port_scan,
    is_ip_report_exists,
)

ip_blueprint = Blueprint("ip_blueprint", __name__, url_prefix="/ip")


@ip_blueprint.route("/", methods=["GET"])
@cross_origin()
def index():
    # a = helper.subdomain_knock_analyzer('nic.in')
    # print(a)
    # save_info_to_database('ip', 'ssl', '14.139.180.56')
    return "This is an ip subroute app"


# @ip_blueprint.route("/discovery", methods=["POST"])
# @cross_origin()
# def run_discovery():
#     content_type = request.headers.get("Content-Type")
#     if content_type == "application/json":
#         data = request.json

#         # data['message']
#         usable_report = helper.is_scan_necessary("ip", "discovery", data["ip"])
#         print("usable report ", usable_report)

#         if isinstance(usable_report, bool) and not usable_report:
#             result = helper.run_nmap_discover("ip", "discovery", data["ip"])
#             data["status"] = "success"
#             data["data"] = result
#         else:
#             information = helper.load_json_file(usable_report)
#             if information is not None:
#                 data["information"] = information
#                 data["status"] = "success"
#             else:
#                 data["status"] = "exception"
#                 data["message"] = "Please try again later"

#         response = make_response(jsonify(data))
#         response.status_code = 200
#         # response.headers["Access-Control-Allow-Origin"] = "*"
#         return response

#         # return
#     else:
#         resp = make_response(
#             jsonify(
#                 {
#                     "status": "invalid",
#                     "message": "content-type not supported",
#                 }
#             )
#         )
#         # resp.headers["Access-Control-Allow-Origin"] = "*"
#         return resp


@ip_blueprint.route("/whois", methods=["POST"])
@cross_origin()
def whois_info():
    """
    The `whois_info` function retrieves and returns information about an IP address using the WHOIS
    protocol.
    :return: The function `whois_info()` returns a response object. The specific response object
    returned depends on the execution path of the code. The possible response objects that can be
    returned are:
    """
    try:
        content_type = request.headers.get("Content-Type")
        if content_type == "application/json":
            data = request.json

            info = is_ip_report_exists("whois", data["ip"])
            print("usable report ", info)

            if info is None or (
                isinstance(info, dict)
                and "status" in list(info.keys())
                and info["status"] in ["rescan", "not exists"]
            ):
                # need to run scan again
                res_base = get_ip_whois_info(data["ip"])

                if (
                    res_base is not None
                    and isinstance(res_base, dict)
                    and "information" in list(res_base.keys())
                ):
                    response = make_response(
                        jsonify(
                            {
                                "message": "Data retrieved successfully",
                                "status": "success",
                                "data": res_base["information"],
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    response = make_response(
                        jsonify(
                            {
                                "message": "Internal Server Error",
                                "status": "exception",
                            }
                        )
                    )
                    response.status_code = 500
                    return response

            else:
                print('info ', info)
                # load the returned data
                if (
                    isinstance(info, dict)
                    and "data" in list(info.keys())
                    and info["data"] is not None
                ):
                    information = info["data"]

                    response = make_response(
                        jsonify(
                            {
                                "message": "Data successfully retrieved",
                                "status": "success",
                                "data": information,
                            }
                        )
                    )
                    response.status_code = 200
                    return response

                else:
                    response = make_response(
                        jsonify(
                            {
                                "message": "Internal Server Error",
                                "status": "exception",
                            }
                        )
                    )
                    response.status_code = 500
                    return response

        else:
            response = make_response(
                jsonify({"message": "Invalid Request", "status": "invalid"})
            )
            response.status_code = 400
            response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    except Exception as identifier:
        response = make_response(
            jsonify(
                {
                    "message": "Internal Server Errror",
                    "error": str(identifier),
                    "status": "exception",
                }
            )
        )
        response.status_code = 500
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response


@ip_blueprint.route("/blacklisted", methods=["POST"])
@cross_origin()
def is_blacklisted():
    """
    The function `is_blacklisted()` checks if a given IP address is blacklisted and returns the
    corresponding information.
    :return: The function `is_blacklisted()` returns a Flask response object. The response object
    contains a JSON payload with a message, status, and data. The status code of the response is also
    set based on the outcome of the function.
    """
    try:
        content_type = request.headers.get("Content-Type")

        if isinstance(content_type, str) and content_type == "application/json":
            data = request.json

            info = is_ip_report_exists("host_info", data["ip"], True, 'ipsum_blacklisted')
            try:
                print("usable report ", info.keys())
                print('data' in list(info.keys()))
                print(info['data'].keys())
            except Exception as i:
                print(i)
                pass

            if info is None or (
                isinstance(info, dict)
                and "status" in list(info.keys())
                and (info["status"] in ["rescan", "not exists"] or info['data'] is not None and 'ipsum_blacklisted' not in list(info['data'].keys()))
            ):
                print('need to run scan again')
                # need to run scan again
                res_base = check_if_ip_is_blacklisted(data["ip"])

                if (
                    res_base is not None
                    and isinstance(res_base, dict)
                    and "ipsum_blacklisted" in list(res_base.keys())
                ):
                    response = make_response(
                        jsonify(
                            {
                                "message": "Data retrieved successfully",
                                "status": "success",
                                "data": {
                                   'ipsum_blacklisted': res_base['ipsum_blacklisted']
                                },
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    response = make_response(
                        jsonify(
                            {
                                "message": "Internal Server Error",
                                "status": "exception",
                            }
                        )
                    )
                    response.status_code = 500
                    return response

            else:
                print('load returned data')
                # load the returned data
                if (
                    isinstance(info, dict)
                    and "data" in list(info.keys())
                    and info["data"] is not None
                    and isinstance(info["data"], dict)
                    and info['data'] is not None and 'ipsum_blacklisted' in list(info['data'].keys())
                ):
                    information = info["data"]
                    # print(information.keys())
                    response = make_response(
                        jsonify(
                            {
                                "message": "Data successfully retrieved",
                                "status": "success",
                                "data": {
                                    'ipsum_blacklisted': information['ipsum_blacklisted']
                                },
                            }
                        )
                    )
                    response.status_code = 200
                    return response

                else:
                    response = make_response(
                        jsonify(
                            {
                                "message": "Internal Server Error",
                                "status": "exception",
                            }
                        )
                    )
                    response.status_code = 500
                    return response

        else:
            response = make_response(
                jsonify({"message": "Invalid Content type", "status": "invalid"})
            )
            response.status_code = 400
            # response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    except Exception as identifier:
        response = make_response(
            jsonify(
                {
                    "message": "Internal Server Errror",
                    "error": str(identifier),
                    "status": "exception",
                }
            )
        )
        response.status_code = 500
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response


@ip_blueprint.route("/host-status", methods=["POST"])
@cross_origin()
def host_alive():
    """
    The `host_alive` function checks if a host is alive by making a request and retrieving the host
    status from a database, and if the status is not available or needs to be rescanned, it runs a host
    discovery scan again.
    :return: The function `host_alive()` returns a Flask response object. The specific response object
    returned depends on the execution path within the function.
    """
    try:
        content_type = request.headers.get("Content-Type")

        if isinstance(content_type, str) and content_type == "application/json":
            data = request.json

            info = is_ip_report_exists("host_info", data["ip"])
            print("usable report ", "info")

            if info is None or (
                isinstance(info, dict)
                and "status" in list(info.keys())
                and info["status"] in ["rescan", "not exists"]
            ):
                # host up is not saved
                # run the host up discovery
                # need to run scan again
                print("need to run scan again")
                res_base = ip_host_alive(data["ip"])

                if (
                    res_base is not None
                    and isinstance(res_base, dict)
                    and "host_status" in list(res_base.keys())
                ):
                    response = make_response(
                        jsonify(
                            {
                                "message": "Data retrieved successfully",
                                "status": "success",
                                "data": res_base["host_status"],
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    response = make_response(
                        jsonify(
                            {
                                "message": "Internal Server Error",
                                "status": "exception",
                            }
                        )
                    )
                    response.status_code = 500
                    return response

            else:
                # check if the info is a valid dict
                print("host status exists" ", info['data']")

                if (
                    isinstance(info, dict)
                    and "data" in list(info.keys())
                    and info["data"] is not None
                    and isinstance(info["data"], dict)
                    and "host_status" in list(info["data"].keys())
                ):
                    # the info object returned from the collection is valid so return that
                    print(info["data"]["host_status"])
                    response = make_response(
                        jsonify(
                            {
                                "message": "success",
                                "status": "success",
                                "data": {"host_status": info["data"]["host_status"]},
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                    # pass
                else:
                    # run the host discovery again
                    print(info)
                    new_info = ip_host_alive(data["ip"])
                    response = make_response(
                        jsonify(
                            {
                                "message": "new scan result",
                                "status": "success",
                                "data": new_info,
                            }
                        )
                    )
                    response.status_code = 200
                    return response
    

        else:
            response = make_response(
                jsonify({"message": "Invalid Content type", "status": "invalid"})
            )
            response.status_code = 400
            # response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    except Exception as identifier:
        response = make_response(
            jsonify(
                {
                    "message": "Internal Server Errror",
                    "error": str(identifier),
                    "status": "exception",
                }
            )
        )
        response.status_code = 500
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response


@ip_blueprint.route("/host-os", methods=["POST"])
@cross_origin()
def host_os():
    """
    The function `host_os()` is a Python function that handles a request to retrieve the operating
    system information of a host based on its IP address.
    :return: a response object with JSON data. The JSON data includes a message, status, and data field.
    The status code of the response is also set.
    """
    try:
        content_type = request.headers.get("Content-Type")

        if isinstance(content_type, str) and content_type == "application/json":
            data = request.json

            info = is_ip_report_exists("host_info", data["ip"], True, "host_status")
            print("usable report ", "info")

            if info is None or (
                isinstance(info, dict)
                and "status" in list(info.keys())
                and info["status"] in ["rescan", "not exists"]
            ):
                # host up is not saved
                # run the host up discovery
                # need to run scan again
                print("need to run scan again")
                res_base = ip_detect_os(data["ip"])

                if (
                    res_base is not None
                    and isinstance(res_base, dict)
                    and "detected_os" in list(res_base.keys())
                ):
                    response = make_response(
                        jsonify(
                            {
                                "message": "Data retrieved successfully",
                                "status": "success",
                                "data": res_base["detected_os"],
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    response = make_response(
                        jsonify(
                            {
                                "message": "Internal Server Error",
                                "status": "exception",
                                # "error": {
                                #     "res_base is not None": res_base is not None,
                                #     "True and isinstance(res_base, dict)": True
                                #     and isinstance(res_base, dict),
                                #     'True and "detected_os" in list(res_base.keys())"': True
                                #     and "detected_os" in list(res_base.keys()),
                                # },
                            }
                        )
                    )
                    response.status_code = 500
                    return response

            else:
                # info had some data
                print("info has detected_os?")
                # check if it had "detected_os"
                # pass

                if (
                    isinstance(info, dict)
                    and "data" in list(info.keys())
                    and info["data"] is not None
                    and isinstance(info["data"], dict)
                    and "detected_os" in list(info["data"].keys())
                ):
                    print(info["data"]["detected_os"])

                    response = make_response(
                        jsonify(
                            {
                                "message": "Data successfully retrieved",
                                "status": "success",
                                "data": {"detected_os": info["data"]["detected_os"]},
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    # scan did not had detected os so run the scan again
                    res_base = ip_detect_os(data["ip"])
                    if (
                        res_base is not None
                        and isinstance(res_base, dict)
                        and "detected_os" in list(res_base.keys())
                    ):
                        response = make_response(
                            jsonify(
                                {
                                    "message": "Data retrieved successfully",
                                    "status": "success",
                                    "data": res_base["detected_os"],
                                }
                            )
                        )
                        response.status_code = 500
                        return response
                    else:
                        response = make_response(
                            jsonify(
                                {
                                    "message": "Internal Server Error",
                                    "status": "exception",
                                    # "error": {
                                    #     "res_base is not None": res_base is not None,
                                    #     "True and isinstance(res_base, dict)": True
                                    #     and isinstance(res_base, dict),
                                    #     'True and "detected_os" in list(res_base.keys())"': True
                                    #     and "detected_os" in list(res_base.keys()),
                                    # },
                                }
                            )
                        )
                        response.status_code = 500
                        return response

        else:
            response = make_response(
                jsonify({"message": "Invalid Content type", "status": "invalid"})
            )
            response.status_code = 400
            # response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    except Exception as identifier:
        response = make_response(
            jsonify(
                {
                    "message": "Internal Server Errror",
                    "error": str(identifier),
                    "status": "exception",
                }
            )
        )
        response.status_code = 500
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response


@ip_blueprint.route("/port-discovery", methods=["POST"])
@cross_origin()
def port_discovery():
    """
    The `port_discovery` function is responsible for handling requests related to port discovery,
    including running scans, retrieving scan results, and handling errors.
    :return: a response object with JSON data. The JSON data includes a "message" field, a "status"
    field, and a "data" field. The specific values of these fields depend on the logic and data within
    the function. The response object also has a status code indicating the success or failure of the
    request.
    """
    try:
        content_type = request.headers.get("Content-Type")

        if isinstance(content_type, str) and content_type == "application/json":
            data = request.json

            info = is_ip_report_exists("open_ports", data["ip"])
            print("usable report ", "info")

            if info is None or (
                isinstance(info, dict)
                and "status" in list(info.keys())
                and info["status"] in ["rescan", "not exists"]
            ):
                print("usable scan rescan not exists")

                # need to run scan again
                print("need to run scan again")
                res_base = ip_port_scan(data["ip"])

                if (
                    res_base is not None
                    and isinstance(res_base, dict)
                    and "thread_ident" in list(res_base.keys())
                ):
                    response = make_response(
                        jsonify(
                            {
                                "message": res_base["message"],
                                "status": "await",
                                "data": {
                                    "thread_ident": res_base["thread_ident"],
                                    "thread_native_id": res_base["thread_native_id"],
                                },
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    response = make_response(
                        jsonify(
                            {
                                "message": "Internal Server Error",
                                "status": "exception",
                            }
                        )
                    )
                    response.status_code = 500
                    return response

            else:
                # info had some data
                print("usable scan exists")
                # check if it had "open_ports"
                # pass

                if (
                    isinstance(info, dict)
                    and "data" in list(info.keys())
                    and info["data"] is not None
                    and isinstance(info["data"], dict)
                    and "open_ports" in list(info["data"].keys())
                ):
                    print(info["data"])

                    response = make_response(
                        jsonify(
                            {
                                "message": "Data successfully retrieved",
                                "status": "success",
                                "data": info["data"],
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    # scan did not had open_ports so run the scan again
                    res_base = ip_port_scan(data["ip"])
                    if (
                        res_base is not None
                        and isinstance(res_base, dict)
                        and "thread_ident" in list(res_base.keys())
                    ):
                        response = make_response(
                            jsonify(
                                {
                                    "message": res_base["message"],
                                    "status": "success",
                                    "data": {
                                        "thread_ident": res_base["thread_ident"],
                                        "thread_native_id": res_base[
                                            "thread_native_id"
                                        ],
                                    },
                                }
                            )
                        )
                        response.status_code = 200
                        return response
                    else:
                        response = make_response(
                            jsonify(
                                {
                                    "message": "Internal Server Error",
                                    "status": "exception",
                                    # "error": {
                                    #     "res_base is not None": res_base is not None,
                                    #     "True and isinstance(res_base, dict)": True
                                    #     and isinstance(res_base, dict),
                                    #     'True and "detected_os" in list(res_base.keys())"': True
                                    #     and "detected_os" in list(res_base.keys()),
                                    # },
                                }
                            )
                        )
                        response.status_code = 500
                        return response

        else:
            response = make_response(
                jsonify({"message": "Invalid Content type", "status": "invalid"})
            )
            response.status_code = 400
            # response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    except Exception as identifier:
        response = make_response(
            jsonify(
                {
                    "message": "Internal Server Errror",
                    "error": str(identifier),
                    "status": "exception",
                }
            )
        )
        response.status_code = 500
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response


@ip_blueprint.route("/active-services", methods=["POST"])
@cross_origin()
def active_services():
    """
    The `active_services` function is a Flask route that handles a POST request to retrieve information
    about active services on a given IP address.
    :return: a Flask response object with a JSON payload. The JSON payload contains a "message" field, a
    "status" field, and a "data" field. The "message" field provides a description of the result, the
    "status" field indicates the status of the request (e.g., "success", "await", "exception"), and the
    "data" field contains the relevant
    """
    try:
        content_type = request.headers.get("Content-Type")

        if isinstance(content_type, str) and content_type == "application/json":
            data = request.json

            info = is_ip_report_exists("active_services", data["ip"])
            print("usable report ", "info")

            if info is None or (
                isinstance(info, dict)
                and "status" in list(info.keys())
                and info["status"] in ["rescan", "not exists"]
            ):
                print("usable scan rescan not exists")

                # need to run scan again
                print("need to run scan again")
                res_base = ip_active_services(data["ip"])

                if (
                    res_base is not None
                    and isinstance(res_base, dict)
                    and "thread_ident" in list(res_base.keys())
                ):
                    response = make_response(
                        jsonify(
                            {
                                "message": res_base["message"],
                                "status": "await",
                                "data": {
                                    "thread_ident": res_base["thread_ident"],
                                    "thread_native_id": res_base["thread_native_id"],
                                },
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    response = make_response(
                        jsonify(
                            {
                                "message": "Internal Server Error",
                                "status": "exception",
                            }
                        )
                    )
                    response.status_code = 500
                    return response

            else:
                # info had some data
                print("usable scan exists")
                # check if it had "active_services"
                # pass

                if (
                    isinstance(info, dict)
                    and "data" in list(info.keys())
                    and info["data"] is not None
                    and isinstance(info["data"], dict)
                    and "active_services" in list(info["data"].keys())
                ):
                    print(info["data"])

                    response = make_response(
                        jsonify(
                            {
                                "message": "Data successfully retrieved",
                                "status": "success",
                                "data": info["data"],
                            }
                        )
                    )
                    response.status_code = 200
                    return response
                else:
                    # scan did not had open_ports so run the scan again
                    res_base = ip_active_services(data["ip"])
                    if (
                        res_base is not None
                        and isinstance(res_base, dict)
                        and "thread_ident" in list(res_base.keys())
                    ):
                        response = make_response(
                            jsonify(
                                {
                                    "message": res_base["message"],
                                    "status": "success",
                                    "data": {
                                        "thread_ident": res_base["thread_ident"],
                                        "thread_native_id": res_base[
                                            "thread_native_id"
                                        ],
                                    },
                                }
                            )
                        )
                        response.status_code = 200
                        return response
                    else:
                        response = make_response(
                            jsonify(
                                {
                                    "message": "Internal Server Error",
                                    "status": "exception",
                                    # "error": {
                                    #     "res_base is not None": res_base is not None,
                                    #     "True and isinstance(res_base, dict)": True
                                    #     and isinstance(res_base, dict),
                                    #     'True and "detected_os" in list(res_base.keys())"': True
                                    #     and "detected_os" in list(res_base.keys()),
                                    # },
                                }
                            )
                        )
                        response.status_code = 500
                        return response

        else:
            response = make_response(
                jsonify({"message": "Invalid Content type", "status": "invalid"})
            )
            response.status_code = 400
            # response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    except Exception as identifier:
        response = make_response(
            jsonify(
                {
                    "message": "Internal Server Errror",
                    "error": str(identifier),
                    "status": "exception",
                }
            )
        )
        response.status_code = 500
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    

@ip_blueprint.route('/locate', methods=['POST'])
@cross_origin()
def locate():
    try:
        content_type = request.headers.get("Content-Type")

        if isinstance(content_type, str) and content_type == "application/json":
            data = request.json

            # running a nslookup takes no time; so no db save is needed
            print("usable report ", "info")

            result = ip_api(data['ip'])

            if result is not None:
                response = make_response(
                    jsonify(
                        {
                            "message": "IP Lookup successful",
                            "status": "success",
                            "data": result
                        }
                    )
                )
                response.status_code = 200
                return response
            elif isinstance(result, str) and len(result)==0:
                response = make_response(
                    jsonify(
                        {
                            "message": "No result found",
                            "status": "success",
                            "data": []
                        }
                    )
                )
                response.status_code = 200

                return response
            else:
                response = make_response(
                    jsonify(
                        {
                            "message": "IP info lookup Failed",
                            "status": "failed",
                            "data": result
                        }
                    )
                )
                response.status_code = 500
        else:
            response = make_response(
                jsonify({"message": "Invalid Content type", "status": "invalid"})
            )
            response.status_code = 400
            # response.headers["Access-Control-Allow-Origin"] = "*"
            return response
    except Exception as identifier:
        response = make_response(
            jsonify(
                {
                    "message": "Internal Server Errror",
                    "error": str(identifier),
                    "status": "exception",
                }
            )
        )
        response.status_code = 500
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response    
