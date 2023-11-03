import requests
from bs4 import BeautifulSoup, ResultSet, Tag

headers = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 QIHU 360SE'  # noqa: E501
}

def crawl_url(uri):
    try:
        

        result = dict()

        if (
            isinstance(uri, str)
            and (uri.startswith("https://") or uri.startswith("http://"))
            and (len(uri.strip("http://")) > 0 or len(uri.strip("https://")) > 0)
        ):  # noqa: E501
            new_uri = uri.strip("https://")
            new_uri = new_uri.strip("http://")

            result = http_schema_crawl(new_uri)

            # return result
        elif isinstance(uri, str) and ("https://" in uri or "http://" in uri):
            result = {'message': 'invalid URL'}
            # return "Please check if there are issues in the provided URL"
        else:
            result['http'] = http_schema_crawl(uri)

            result['https'] = https_schema_crawl(uri)
        
        return result
            # return result

    except Exception as e:
        print("exception in crawling ", uri)
        print(type(e))
        print(e)
        return None


def http_schema_crawl(base_uri):
    try:
        uri = "http://" + base_uri
        response = requests.get(uri, headers=headers)
        report = dict()

        if response.status_code == 200:
            final_url = response.url  # Get the final URL after any redirects

            if final_url == uri:
                report["redirects To"] = None
                print("no redirect")
            else:
                report["redirects To"] = final_url
                print("redirect")

            soup = BeautifulSoup(response.content, "html.parser")
            # page_html = response.content
            #
            script_elements = soup.select("script[src]")

            if (
                script_elements is not None
                and isinstance(script_elements, ResultSet)
                and len(script_elements) > 0
            ):  # noqa: E501
                report["has external scripts"] = True
                report["script files"] = []

                for index, script_element in enumerate(script_elements):
                    # print(index)

                    sub_url = script_element.get("src", None)
                    cross_origin = script_element.get("crossorigin", None)
                    script_type = script_element.get("type", None)

                    tmp1 = {
                        "route": sub_url,
                        "cross origin": cross_origin, 
                        "script_type": script_type
                            }

                    if not str(sub_url).startswith(final_url) and not str(sub_url).startswith("/"):  # noqa: E501
                        tmp1["type"] = "external"
                    else:
                        tmp1["type"] = "internal"

                    report["script files"].append(tmp1)  # noqa: E501

            link_elements = soup.select("a[href]")
            # print(link_elements)
            # print(type(link_elements))
            if (
                link_elements is not None
                and isinstance(link_elements, ResultSet)
                and len(link_elements) > 0
            ):  # noqa: E501
                report["has links"] = True
                report["links"] = []

                for index, link_element in enumerate(link_elements):
                    if link_element is not None and isinstance(link_element, Tag):
                        sub_url = link_element["href"]
                        contents = link_element.contents
                        serializable_data = []
                        tmp2 = {
                            "link": str(sub_url),
                            "type": None,
                            "contents": None,
                            "inner": None,
                        }  # noqa: E501
                        if isinstance(contents, list):
                            for content in contents:
                                serializable_data.append(str(content))

                        tmp2["contents"] = serializable_data

                        if not str(sub_url).startswith(final_url) and not str(sub_url).startswith("/"):  # noqa: E501
                            tmp2["type"] = "external"
                        else:
                            tmp2["type"] = "internal"

                    report["links"].append(tmp2)
            else:
                report["has links"] = False

            # return type(link_elements)
        return report

    except Exception as e:
        print("Exception in crawling", base_uri)
        print(type(e))
        print(e)
        return None


def https_schema_crawl(base_uri):
    try:
        uri = "https://" + base_uri
        response = requests.get(uri, headers=headers    )
        report = dict()

        if response.status_code == 200:
            final_url = response.url  # Get the final URL after any redirects

            if final_url == uri:
                report["redirects To"] = None
                print("no redirect")
            else:
                report["redirects To"] = final_url
                print("redirect")

            soup = BeautifulSoup(response.content, "html.parser")
            # page_html = response.content
            #
            script_elements = soup.select("script[src]")

            if (
                script_elements is not None
                and isinstance(script_elements, ResultSet)
                and len(script_elements) > 0
            ):  # noqa: E501
                report["has external scripts"] = True
                report["script files"] = []

                for index, script_element in enumerate(script_elements):
                    # print(index)

                    sub_url = script_element.get("src", None)
                    cross_origin = script_element.get("crossorigin", None)
                    script_type = script_element.get("type", None)

                    tmp1 = {
                        "route": sub_url,
                        "cross origin": cross_origin, 
                        "script_type": script_type
                            }

                    if not str(sub_url).startswith(final_url) and not str(sub_url).startswith("/"):  # noqa: E501
                        tmp1["type"] = "external"
                    else:
                        tmp1["type"] = "internal"

                    report["script files"].append(tmp1)  # noqa: E501

            link_elements = soup.select("a[href]")
            # print(link_elements)
            # print(type(link_elements))
            if (
                link_elements is not None
                and isinstance(link_elements, ResultSet)
                and len(link_elements) > 0
            ):  # noqa: E501
                report["has links"] = True
                report["links"] = []

                for index, link_element in enumerate(link_elements):
                    if link_element is not None and isinstance(link_element, Tag):
                        sub_url = link_element["href"]
                        contents = link_element.contents
                        serializable_data = []
                        tmp2 = {
                            "link": str(sub_url),
                            "type": None,
                            "contents": None,
                            "inner": None,
                        }  # noqa: E501
                        if isinstance(contents, list):
                            for content in contents:
                                serializable_data.append(str(content))

                        tmp2["contents"] = serializable_data

                        if not str(sub_url).startswith(final_url) and not str(sub_url).startswith("/"):  # noqa: E501
                            tmp2["type"] = "external"
                        else:
                            tmp2["type"] = "internal"

                    report["links"].append(tmp2)
            else:
                report["has links"] = False

            # return type(link_elements)
        return report

    except Exception as e:
        print("Exception in crawling", base_uri)
        print(type(e))
        print(e)
        return None
