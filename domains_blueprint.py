from flask import Blueprint, make_response, request, jsonify
from flask_cors import cross_origin
import helper

domain_blueprint = Blueprint("domain_blueprint", __name__, url_prefix="/domain")


@domain_blueprint.route("/")
@cross_origin()
def index():
    # a = helper.subdomain_knock_analyzer('nic.in')
    # print(a)
    return "This is an domain subroute app"


@domain_blueprint.route("/ssl-info", methods=["POST"])
@cross_origin()
def ssl_info_view():
    content_type = request.headers.get("Content-Type")
    if content_type == "application/json":
        data = request.json
        # it will only work with domain names and IP Address.
        # it will not accept URLs

        is_valid_arg = helper.identify_input(data["uri"])

        if is_valid_arg not in [
            "domain",
        ]:
            response = make_response(
                jsonify(
                    {
                        "message": "Not a valid input. This tool only accepts Domain names",  # noqa: E501
                        "status": "failed",
                    }
                )
            )
            response.status_code = 400
            # response.headers['Access-Control-Allow-Origin'] = "*"
            return response
        else:
            usable_report = helper.is_scan_necessary("domain", "ssl", data["uri"])

            if isinstance(usable_report, bool) and not usable_report:
                scan_status = helper.get_ssl_info(data["uri"])
                if scan_status is None:
                    data[
                        "message"
                    ] = "There was issue with scanning. Please contact admin"  # noqa: E501
                    data["status"] = "exception"
                else:
                    data["message"] = "SSL information was returned"  # noqa: E501
                    data["information"] = scan_status
            else:
                information = helper.load_json_file(usable_report)
                if information is not None:
                    data["information"] = information
                    data["status"] = "success"
                else:
                    data["status"] = "exception"
                    data["message"] = "Please try again later"

            response = make_response(jsonify(data))
            if data["status"] == "success":
                response.status_code = 200
            else:
                response.status = 500
            # response.headers['Access-Control-Allow-Origin'] = "*"
            return response
    else:
        response = make_response(jsonify(
            {
                "status": "invalid",
                "message": "content-type not supported",
            }
        ))
        response.status_code = 200
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response



@domain_blueprint.route("/subdomain", methods=["POST"])
@cross_origin()
def subdomain_info_view():
    content_type = request.headers.get("Content-Type")
    if content_type == "application/json":
        data = request.json
        usable_report = helper.is_scan_necessary("domain", "subdomain", data["uri"])

        print('usable report ', usable_report)

        if isinstance(usable_report, bool) and not usable_report:
            scan_status = helper.subdomain_knock_analyzer(data['uri'])
            if scan_status is not None and isinstance(scan_status, dict):  # noqa: E501
                response = make_response(jsonify(scan_status))
                response.status_code = 200
                # response.headers["Access-Control-Allow-Origin"] = "*"
                return response
                # return jsonify(scan_status)
            else:
                # return jsonify(
                    
                # )
                response = make_response(jsonify({"status": "exception", "message": scan_status["message"]}))
                response.status_code = 200
                # response.headers["Access-Control-Allow-Origin"] = "*"
                return response

        else:
            information = helper.load_json_file(usable_report)
            if information is not None:
                data["information"] = information
                data["status"] = "success"
                # return jsonify(data)
                response = make_response(jsonify(data))
                response.status_code = 200
                # response.headers["Access-Control-Allow-Origin"] = "*"
                return response

            else:
                data["status"] = "exception"
                data["message"] = "Please try again later"

                response = make_response(jsonify(data))
                response.status_code = 200
                # response.headers["Access-Control-Allow-Origin"] = "*"
                return response
    
    else:
        resp = make_response(
            jsonify(
                {
                    "status": "invalid",
                    "message": "content-type not supported",
                }
            )
        )
        resp.status_code = 400
        # resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp


@domain_blueprint.route("/whois", methods=["POST"])
@cross_origin()
def whois_info_view():
    content_type = request.headers.get("Content-Type")
    if content_type == "application/json":
        data = request.json
        usable_report = helper.is_scan_necessary("domain", "whois", data["uri"])
        print("usable report ", usable_report)

        if isinstance(usable_report, bool) and not usable_report:
            scan_status = helper.get_whois_info(data["uri"])
            if scan_status is None:
                data["message"] = "There was issue with scanning. Please contact admin"
                data["status"] = "exception"
            else:
                data["message"] = "WhoIs information was returned"  # noqa: E501
                data["information"] = scan_status
        else:
            information = helper.load_json_file(usable_report)
            if information is not None:
                data["information"] = information
                data["status"] = "success"
            else:
                data["status"] = "exception"
                data["message"] = "Please try again later"

        response = make_response(jsonify(data))
        response.status_code = 200
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response
    else:
        resp = make_response(
            jsonify(
                {
                    "status": "invalid",
                    "message": "content-type not supported",
                }
            )
        )
        resp.status_code = 400
        # resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp


@domain_blueprint.route("/crawl", methods=["POST"])
@cross_origin()
def get_site_info():
    try:
        content_type = request.headers.get("Content-Type")
        if content_type == "application/json":
            data = request.json
            usable_report = helper.is_scan_necessary("domain", "webcrawl", data["uri"])
            print("usable report ", usable_report)

            if isinstance(usable_report, bool) and not usable_report:
                scan_status = helper.webcrawl_helper(data["uri"])
                if scan_status is None:
                    data[
                        "message"
                    ] = "There was issue with scanning. Please contact admin"  # noqa: E501
                    data["status"] = "exception"
                else:
                    data["status"] = "success"
                    data["message"] = "SSL information was returned"  # noqa: E501
                    data["information"] = scan_status
            else:
                information = helper.load_json_file(usable_report)
                if information is not None:
                    data["information"] = information
                    data["status"] = "success"
                else:
                    data["status"] = "exception"
                    data["message"] = "Please try again later"

        # return
        response = make_response(jsonify(data))
        response.status_code = 200
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    except Exception as identifier:
        # return
        resp = make_response(
            jsonify({"status": "exception", "message": str(identifier)})
        )
        resp.status_code = 500
        # response.headers["Access-Control-Allow-Origin"] = "*"

        return resp


@domain_blueprint.route("/malware-source", methods=["POST", "OPTIONS"])
@cross_origin()
def check_safety():
    content_type = request.headers.get("Content-Type")
    print(request.headers)
    if content_type == "application/json" and request.method == "POST":
        data = request.json
        result = helper.is_malware_source(data["uri"])
        data["status"] = "success"
        data["is_malware_source"] = result

        response = make_response(jsonify(data))
        response.status_code = 200

        # response.headers["Access-Control-Allow-Origin"] = "*"
        print('post')
        print(response.headers)
        print(response.data)
        return response
    
    elif request.method == "OPTIONS":
        resp = make_response(jsonify({'status': "invalid", "message": 'request method not supported'}))
        resp.status_code = 403
        resp.headers['Access-Control-Allow-Origin'] = "*"
        print('options')
        print(resp)
        return resp
    else:
        resp = make_response(
            jsonify(
                {
                    "status": "invalid",
                    "message": "content-type not supported",
                }
            )
        )
        resp.status_code = 400
        # resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp


@domain_blueprint.route("/discovery", methods=["POST"])
@cross_origin()
def run_discovery():
    content_type = request.headers.get("Content-Type")
    if content_type == "application/json":
        data = request.json
        
        # data['message']
        usable_report = helper.is_scan_necessary("domain", "discovery", data["uri"])
        print("usable report ", usable_report)

        if isinstance(usable_report, bool) and not usable_report:
            result = helper.run_nmap_discover("domain", "discovery", data["uri"])
            data["status"] = "success"
            data["data"] = result
        else:
            information = helper.load_json_file(usable_report)
            if information is not None:
                data["information"] = information
                data["status"] = "success"
            else:
                data["status"] = "exception"
                data["message"] = "Please try again later"

        response = make_response(jsonify(data))
        response.status_code = 200
        # response.headers["Access-Control-Allow-Origin"] = "*"
        return response

        # return
    else:
        resp = make_response(
            jsonify(
                {
                    "status": "invalid",
                    "message": "content-type not supported",
                }
            )
        )
        # resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp
