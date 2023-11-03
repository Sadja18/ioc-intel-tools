from datetime import datetime, timedelta
import mongoengine


# The class "Report" is a MongoDB document with fields for scan type, information, creation date, and
# update date.
class Report(mongoengine.Document):
    scan_type = mongoengine.StringField()
    information = mongoengine.DynamicField(required=True)
    createdAt = mongoengine.DateTimeField(default=datetime.utcnow())
    updatedAt = mongoengine.DateTimeField(default=datetime.utcnow())
    version = mongoengine.IntField(min_value=0, default=0)

    meta = {"allow_inheritance": True, 'abstract': True}


# The `IpReport` class is a subclass of `Report` that includes an `ipAddress` field and is designed to
# be inherited from.
class IpReport(Report):
    ipAddress = mongoengine.StringField()
    # meta = {"allow_inheritance": True}
    meta = {"allow_inheritance": True, 'abstract': True}



class DomainReport(Report):
    domain = mongoengine.StringField()
    # meta = {"allow_inheritance": True}
    meta = {"allow_inheritance": True, 'abstract': True}



class IpActiveServiceReport(IpReport):
    meta = {"index_cls": False, "collection": "ip_active_service_report"}


class IpOpenPortDiscoveryReport(IpReport):
    meta = {"index_cls": False, "collection": "ip_open_port_report"}


class IpServiceVersionsReport(IpReport):
    meta = {"index_cls": False, "collection": "ip_service_version_report"}


class IpHostReport(IpReport):
    meta = {"index_cls": False, "collection": "ip_host_report"}


class IpWhoIsReport(IpReport):
    meta = {"index_cls": False, "collection": "ip_whois_report"}


class IpPortRequestReport(IpReport):
    meta = {"index_cls": False, "collection": "ip_port_request_report"}


class DomainSubDomainReport(DomainReport):
    meta = {"index_cls": False, "collection": "domain_subdomain_report"}


class DomainSslReport(DomainReport):
    meta = {"index_cls": False, "collection": "domain_ssl_report"}


class DomainWebCrawlReport(DomainReport):
    meta = {"index_cls": False, "collection": "domain_webcrawl_report"}


# The class DomainHostReport is a subclass of IpReport and is used to generate reports for domain
# hosts.
class DomainHostReport(IpReport):
    meta = {"index_cls": False, "collection": "domain_host_report"}


def get_ip_collection_class(report_type):
    """
    The function `get_ip_collection_class` returns the appropriate class based on the given
    `report_type` parameter.
    
    :param report_type: The `report_type` parameter is a string that represents the type of IP report
    you want to generate. It can have one of the following values:
    :return: The function `get_ip_collection_class` returns the class corresponding to the given
    `report_type` parameter. If the `report_type` is found in the `collection_class_dict` dictionary,
    the corresponding class is returned. Otherwise, `None` is returned.
    """
    print("report type for ", report_type)
    collection_class_dict = {
        "host_info": IpHostReport,
        "whois": IpWhoIsReport,
        "open_ports": IpOpenPortDiscoveryReport,
        "port_request": IpPortRequestReport,
        "active_services": IpActiveServiceReport,
        "service_versions": IpServiceVersionsReport,
    }

    if report_type in list(collection_class_dict.keys()):
        return collection_class_dict[report_type]
    else:
        return None

def convert_keys_to_str(d):
    """
    The function `convert_keys_to_str` converts all keys in a dictionary (and nested dictionaries) from
    integers to strings.
    
    :param d: The parameter `d` is a dictionary or a list that you want to convert
    :return: a dictionary or list with all the keys converted to strings.
    """
    if isinstance(d, dict):
        converted_dict = {}
        for key, value in d.items():
            if isinstance(key, int):
                key = str(key)
            if isinstance(value, (dict, list)):
                converted_dict[key] = convert_keys_to_str(value)
            else:
                converted_dict[key] = value
        return converted_dict
    elif isinstance(d, list):
        converted_list = []
        for item in d:
            if isinstance(item, (dict, list)):
                converted_list.append(convert_keys_to_str(item))
            else:
                converted_list.append(item)
        return converted_list
    return d

    
def save_ip_report_to_collection(report_type, ip_address, data, sub_key_of_info=False):
    """
    The function `save_ip_report_to_collection` saves an IP report to a collection in a database, either
    updating an existing document or creating a new one.
    
    :param report_type: The `report_type` parameter is a string that specifies the type of report. It is
    used to determine the collection name where the report will be saved
    :param ip_address: The IP address for which the report is being saved
    :param data: The `data` parameter is a dictionary that contains the information to be saved in the
    collection. It can have any key-value pairs depending on the specific requirements of the collection
    :param sub_key_of_info: The parameter "sub_key_of_info" is a boolean flag that indicates whether the
    "data" parameter should be added as a sub-key of the "information" field in the document. If it is
    set to True, the "data" will be added as a sub-key of the "information", defaults to False
    (optional)
    :return: a dictionary with a 'status' key. The value of 'status' can be 'updated', 'not updated',
    'created', 'failed', or 'invalid report type' depending on the execution of the function.
    """
    try:
        collection_name = get_ip_collection_class(report_type)

        if collection_name is not None:
            # prepare the object to insert

            # first check if document already exists
            try:
                existing_object = collection_name.objects.get(ipAddress=ip_address)

                print('existing object')
                print(existing_object.id)
                
                print(existing_object.information)
                last_updated = existing_object.updatedAt  
                # created_at = existing_object.createdAt

                # Check if the last update was more than 5 days ago
                five_days_ago = datetime.now() - timedelta(days=5)
                print(type(five_days_ago))
                if last_updated <= five_days_ago or sub_key_of_info:
                    # :
                    print('sub key info')
                    # print(data)
                    info = existing_object.information
                    for key in list(data.keys()):
                        info[key] = data[key]

                    new_info = convert_keys_to_str(info)
                    print('new info update')
                    # print(new_info)
                    
                    save_status = collection_name.objects(ipAddress = ip_address).upsert_one(information=new_info, updatedAt=datetime.utcnow())
                    # save_value  = existing_object.save()
                    print("save::  ", save_status)
                    return {'status': 'updated'}
                else:
                    return {'status': 'not updated'}
            except mongoengine.DoesNotExist as error:
                # print(error)
                print("does not exist occured in objects.get")
                # print(error)
                print(type(error))

                new_info = convert_keys_to_str(data)
                print('new info create')
                # print(new_info)
                # If it doesn't exist, create a new document and save it
                new_object = collection_name(scan_type='ip', information=new_info, ipAddress=ip_address, version=0)
                new_object.save()
                return {'status': 'created'}
            except Exception as e:
                print("exception occured in objects.get")
                print(e)
                print(type(e))
                return {'status': 'failed'}
            
        else:
            print("collection_name ", collection_name)
            return {'status': 'invalid report type'}
    except Exception as identifier:
        print(identifier)
        print('exception saving to collection ')
        return None
