"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import requests, json
import urllib.parse
from .constants import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger("fortinet-fortiweb-cloud")


class FortiWeb(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get("api_key")
        url = config.get("server_url").strip("/")
        if not url.startswith("https://") and not url.startswith("http://"):
            self.url = "https://{0}/v2".format(url)
        else:
            self.url = url + "/v2"
        self.verify_ssl = config.get("verify_ssl")

    def make_rest_call(self, url, method="GET", data=None, params=None):
        try:
            url = self.url + url
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": "Basic " + self.api_key
            }
            response = requests.request(method, url, data=data, params=params, headers=headers, verify=self.verify_ssl)
            if response.ok or response.status_code == 204:
                logger.info("Successfully got response for url {0}".format(url))
                if "json" in str(response.headers):
                    return response.json()
                else:
                    return response
            else:
                logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
                raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError("SSL certificate validation failed")
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError("The request timed out while trying to connect to the server")
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                "The server did not send any data in the allotted amount of time")
        except requests.exceptions.ConnectionError:
            raise ConnectorError("Invalid Credentials")
        except Exception as err:
            raise ConnectorError(str(err))


def get_incident_dashboard_details(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/ta/dashboard"
        query_params = {
            "widget_id": WIDGET_NAMES.get(params.get("widget_id"), params.get("widget_id")),
            "action": params.get("action").lower() if params.get("action") else "",
            "host": params.get("host"),
            "time_range": params.get("time_range")
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ""}
        response = fw.make_rest_call(endpoint, params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_list(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/ta/incidents"
        if params.get("filter"):
            filter = json.dumps(params.get("filter"))
            filter = urllib.parse.quote(filter)
            endpoint = endpoint + "?filter={0}".format(filter)
        query_params = {
            "time_range": params.get("time_range"),
            "size": params.get("size"),
            "page": params.get("page")
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ""}
        response = fw.make_rest_call(endpoint, params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_details(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/ta/incidents/{0}".format(params.get("incident_id"))
        response = fw.make_rest_call(endpoint)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_timeline_details(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/ta/incidents/{0}/timeline".format(params.get("incident_id"))
        response = fw.make_rest_call(endpoint)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_insight_events_summary(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/ta/insight/summary"
        response = fw.make_rest_call(endpoint)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_aggregated_details(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/ta/incidents/{0}/aggs".format(params.get("incident_id"))
        query_params = {
            "name": GROUP_BY.get(params.get("name"), params.get("name"))
        }
        response = fw.make_rest_call(endpoint, params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_insight_events(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/ta/insight"
        query_params = {
            "type": EVENT_TYPE.get(params.get("type"), params.get("type")),
            "cursor": params.get("cursor"),
            "size": params.get("size"),
            "forward": params.get("forward")
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ""}
        response = fw.make_rest_call(endpoint, params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_ip_protection(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/waf/apps/{ep_id}/ip_protection".format(ep_id=params.get("epid"))
        response = fw.make_rest_call(endpoint)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def add_ip_protection(config, params):
    try:
        fw = FortiWeb(config)
        query_params = get_ip_protection(config, params).get("result")

        # sanitizing the ip_list because fortiweb when the IP is removed it does not remove well
        for idx in reversed(range(len(query_params["configs"]["ip_list"]))):
            if not isinstance(query_params["configs"]["ip_list"][idx].get("ip"), str):
                del query_params["configs"]["ip_list"][idx]

        endpoint = "/waf/apps/{ep_id}/ip_protection".format(ep_id=params.get("epid"))
        if not isinstance(query_params["configs"]["ip_list"], list):
            query_params["configs"]["ip_list"] = []
        ip_type = IP_TYPE.get(params.get("iptype"))
        query_params["configs"]["ip_list"].append({"type": ip_type, "ip": params.get("ipaddress")})
        response = fw.make_rest_call(endpoint, data=json.dumps(query_params), method="PUT")
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def delete_ip_protection(config, params):
    try:
        fw = FortiWeb(config)
        query_params = get_ip_protection(config, params).get("result")
        endpoint = "/waf/apps/{ep_id}/ip_protection".format(ep_id=params.get("epid"))

        ip_type = IP_TYPE.get(params.get("iptype"))
        for idx in range(len(query_params["configs"]["ip_list"])):
            try:
                ips = query_params["configs"]["ip_list"][idx].get("ip", "").split(",")
            except:
                continue
            if query_params["configs"]["ip_list"][idx].get("type") == ip_type and params.get("ipaddress") in ips:
                ips.remove(params.get("ipaddress"))
                if len(ips) == 0:
                    ips = None
                    query_params["configs"]["ip_list"][idx]["ip"] = ips
                else:
                    query_params["configs"]["ip_list"][idx]["ip"] = ",".join(ips)
                logger.debug("IP Addresses {0}: {1}".format(idx, ips))
                break

        # sanitizing the ip_list because fortiweb when the IP is removed it does not remove well
        for idx in reversed(range(len(query_params["configs"]["ip_list"]))):
            if not isinstance(query_params["configs"]["ip_list"][idx].get("ip"), str):
                del query_params["configs"]["ip_list"][idx]
        response = fw.make_rest_call(endpoint, data=json.dumps(query_params), method="PUT")
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def update_geo_ip_block_list(config, params):
    try:
        fw = FortiWeb(config)
        query_params = get_ip_protection(config, params).get("result")
        query_params['configs']['ip_list'] = [ip_entry for ip_entry in query_params['configs']['ip_list'] if
                                              ip_entry['ip'] not in [None, "", "null"]]
        endpoint = "/waf/apps/{ep_id}/ip_protection".format(ep_id=params.get("epid"))
        if params.get("block_country_list"):
            original_list = query_params["configs"]["block_country_list"]
            if params.get("operation_to_perform") == "Add Countries To Block List":
                original_list = list(set(original_list) | set(params["block_country_list"]))
            else:
                original_list = [country for country in original_list if country not in params["block_country_list"]]
            query_params["configs"]["block_country_list"] = original_list
            response = fw.make_rest_call(endpoint, data=json.dumps(query_params), method="PUT")
            return response
        else:
            logger.error(f"\n\nNo countries selected. Please select at least one country to proceed.\n\n")
            return {"detail": "No countries selected. Please select at least one country to proceed."}
    except Exception as err:
        raise ConnectorError(str(err))


def get_application_list(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = "/waf/apps"
        if params.get("filter"):
            filter = json.dumps(params.get("filter"))
            filter = urllib.parse.quote(filter)
            endpoint = endpoint + "?filter={0}".format(filter)
        query_params = {
            "size": params.get("size"),
            "cursor": params.get("cursor"),
            "forward": params.get("forward")
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ""}
        response = fw.make_rest_call(endpoint, params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def execute_an_api_call(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = params.get("endpoint")
        http_method = params.get("method")
        query_params = params.get("query_params") if params.get("query_params") else None
        payload = json.dumps(params.get("payload")) if params.get("payload") else None
        logger.debug("Payload: {0}".format(payload))
        response = fw.make_rest_call(endpoint, http_method, params=query_params, data=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def check_health(config):
    try:
        response = get_application_list(config, params={})
        if response:
            return True
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


operations = {
    "get_incident_dashboard_details": get_incident_dashboard_details,
    "get_incident_list": get_incident_list,
    "get_incident_details": get_incident_details,
    "get_incident_timeline_details": get_incident_timeline_details,
    "get_insight_events_summary": get_insight_events_summary,
    "get_incident_aggregated_details": get_incident_aggregated_details,
    "get_insight_events": get_insight_events,
    "get_application_list": get_application_list,
    "get_ip_protection": get_ip_protection,
    "add_ip_protection": add_ip_protection,
    "delete_ip_protection": delete_ip_protection,
    "update_geo_ip_block_list": update_geo_ip_block_list,
    "execute_an_api_call": execute_an_api_call
}
