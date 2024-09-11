import requests
import logging
import json

from zohoanalytics import ZohoAnalytics, generate_access_token,analyticsMap

logger = logging.getLogger(__name__)


def do(payload, config, plugin_config, inputs):
    client_id = config.get("zanalytics_connection").get("client-id", "")
    client_secret = config.get("zanalytics_connection").get("client-secret", "")
    refreshtoken = config.get("zanalytics_connection").get("refreshtoken", "")
    dc = config.get("zanalytics_connection").get("dc", "")
    if payload.get("parameterName") == "org_id":
        GET_ORGS = analyticsMap.get(dc)+"/restapi/v2/orgs"
        token=generate_access_token(refreshtoken,client_id, client_secret,dc).get("access_token")
        headers = {'Authorization': 'Zoho-oauthtoken ' + token,'Content-Type': 'application/json'}
        response = requests.get(GET_ORGS, headers=headers)
        logger.exception(response.json())
        # Build choices
        choices = []

        if response.status_code == 200:
            ds = response.json().get("data").get("orgs", [])
            for item in ds:
                if item["role"] == "Account Admin" or item["role"] == "Organization Admin" :
                    choices += [{"value": item["orgId"], "label": item["orgName"]}]

        else:
            logger.exception("Organisations could not be retrieved")
            
        return {"choices": choices}
    if payload.get('parameterName') == "workspace_id":

        # Request the connections

        LIST_COLLECTIONS = analyticsMap.get(dc)+"/restapi/v2/workspaces"
        token=generate_access_token(refreshtoken,client_id, client_secret,dc).get("access_token")
        headers = {'Authorization': 'Zoho-oauthtoken ' + token,'Content-Type': 'application/json','ZANALYTICS-ORGID' : ""+config["org_id"]}
        response = requests.get(LIST_COLLECTIONS, headers=headers)

        # Build choices

        choices = []

        if response.status_code == 200:
            coll = response.json().get("data").get("ownedWorkspaces", [])
            for item in coll:
                choices += [{"value": item["workspaceId"], "label": item["workspaceName"]}]
        else:
            logger.exception("Collection could not be retrieved")

        return {"choices": choices}
    if payload.get("parameterName") == "dataset_id":
        GET_DATASETS = analyticsMap.get(dc)+"/restapi/v2/workspaces/"+config["workspace_id"]+"/views"
        token=generate_access_token(refreshtoken,client_id, client_secret,dc).get("access_token")
        headers = {'Authorization': 'Zoho-oauthtoken ' + token,'Content-Type': 'application/json','ZANALYTICS-ORGID' : ""+config["org_id"]}
        response = requests.get(GET_DATASETS, headers=headers)
        logger.exception(response.json())
        # Build choices

        choices = []

        if response.status_code == 200:
            ds = response.json().get("data").get("views", [])
            for item in ds:
                if item["viewType"] == "Table":
                    choices += [{"value": item["viewId"], "label": item["viewName"]}]

        else:
            logger.exception("Dataset could not be retrieved")

        return {"choices": choices}
    if payload.get("parameterName") == "column_id":
        GET_COLUMNS = analyticsMap.get(dc)+"/restapi/v2/views/"+config["dataset_id"]
        token=generate_access_token(refreshtoken,client_id, client_secret,dc).get("access_token")
        headers = {'Authorization': 'Zoho-oauthtoken ' + token,'Content-Type': 'application/json','ZANALYTICS-ORGID' : ""+config["org_id"]}
        payload={}
        payload["CONFIG"]=json.dumps({"withInvolvedMetaInfo":"true"})
        response = requests.get(GET_COLUMNS,params=payload, headers=headers)
        logger.info(response.json())
        
        choices = []

        if response.status_code == 200:
            cols = response.json().get("data").get("views").get("columns",[])
            for col in cols:
                choices += [{"value": col["columnName"], "label": col["columnName"]}]
        else:
            logger.exception("Collection could not be retrieved")
        return {"choices": choices}
            