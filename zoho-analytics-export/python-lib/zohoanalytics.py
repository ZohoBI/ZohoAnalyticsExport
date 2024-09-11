import json
import requests
import logging
import math
import urllib
import pandas as pd



fieldSetterMap = {
    'boolean':  'BOOLEAN',
    'tinyint':  'NUMBER',
    'smallint': 'NUMBER',
    'int':      'NUMBER',
    'bigint':   'NUMBER',
    'float':    'DECIMAL_NUMBER',
    'double':   'DECIMAL_NUMBER',
    'date':     'DATE',
    'string':   'PLAIN',
    'array':    'PLAIN',
    'map':      'PLAIN',
    'object':   'PLAIN'
}


analyticsMap = {
    "US":"https://analytics.zoho.com",
    "EU":"https://analytics.zoho.eu",
    "IN":"https://analytics.zoho.in",
    "AU":"https://analytics.zoho.com.au",
    "JP":"https://analytics.zoho.jp",
    "CN":"https://analytics.zoho.com.cn",
    "CA":"https://analytics.zohocloud.ca"
}

accountsMap = {
    "US":"https://accounts.zoho.com",
    "EU":"https://accounts.zoho.eu",
    "IN":"https://accounts.zoho.in",
    "AU":"https://accounts.zoho.com.au",
    "JP":"https://accounts.zoho.jp",
    "CN":"https://accounts.zoho.com.cn",
    "CA":"https://accounts.zohocloud.ca"
}

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
                    format='zoho-analytics plugin %(levelname)s - %(message)s')


# Main interactor object
class ZohoAnalytics(object):

    def __init__(self, token,org_id,dc):
        self.token = token
        self.dc=dc
        self.headers = {
            'Authorization': 'Zoho-oauthtoken ' + self.token,
            'Content-Type': 'application/json',
            'ZANALYTICS-ORGID' : ""+org_id
        }
        self.columns_with_date = None
        self.columns_with_boolean = None
        self.columns =None

    def get_datasets(self, workpsace_id=None):
        endpoint = self.get_datasets_base_url(workpsace_id=workpsace_id)
        response = requests.get(endpoint, headers=self.headers)
        return response

    def get_dataset_by_name(self, name, workpsace_id=None):
        data = self.get_datasets(workpsace_id=workpsace_id)
        datasets = data.json().get("data").get('views')
        ret = []
        if datasets:
            for dataset in datasets:
                if dataset['viewName'] == name:
                    ret.append(dataset['viewId'])
        return ret

    def delete_dataset(self, dsid, workpsace_id=None):
        endpoint = '{}/{}'.format(self.get_datasets_base_url(workpsace_id=workpsace_id), dsid)
        response = requests.delete(endpoint, headers=self.headers)
        assert_response_ok(response, while_trying="deleting {}".format(dsid))
        logger.info("[+] Deleted existing Power BI dataset {} (response code: {})...".format(
            dsid, response.status_code
        ))
        return response

    def empty_dataset(self, dsid, table="ExportFromDSS", workpsace_id=None):
        # Empty an existing dataset's content, without deleting the dataset
        #    keeping related reports intact
        TABLE_ROWS_API=analyticsMap.get(self.dc)+"/restapi/v2/workspaces/{}/views/{}/data"
        response = self._delete(
            TABLE_ROWS_API.format(
                workpsace_id,
                dsid,
                table
            ),
            fail_on_errors=False
        )
        return response
    
    
    def create_dataset_from_schema(self, workspace_name=None, table="ExportFromDSS", workpsace_id=None, schema=None):
        columns = []
        for column in schema["columns"]:
            new_column = {}
            new_column["COLUMNNAME"] = column["name"]
            new_column["DATATYPE"] = fieldSetterMap.get(column["type"], "PLAIN")
            columns.append(new_column)
        payload = {'CONFIG' : json.dumps({
              "tableDesign":
             {
                    "TABLENAME": table,
                    "COLUMNS": columns
            
             }
          })}

        logger.info(payload)
        TABLE_DATASETS_API=analyticsMap.get(self.dc)+"/restapi/v2/workspaces/{group_id}/tables"
        json_response = self.post(
            TABLE_DATASETS_API.format(group_id=workpsace_id),
            data=payload
        )
        return json_response

    def register_formattable_columns(self, schema):
        self.columns_with_date = []
        self.columns_with_boolean = []
        self.columns=[]
        for column in schema["columns"]:
            self.columns.append(column["name"])
            if column["type"] == "date":
                self.columns_with_date.append(column["name"])
            if column["type"] == "boolean":
                self.columns_with_boolean.append(column["name"])
        if (len(self.columns_with_date) > 0) or (len(self.columns_with_boolean) > 0):
            self.json_filter = self.parse_formattable_values
        else:
            self.json_filter = json.dumps

    def filter_group_by_name(self, groups, pbi_workspace):
        lowercase_workspace_name = pbi_workspace.lower()
        for group in groups:
            if group.get("workspaceName", "").lower() == lowercase_workspace_name:
                return group
        return {}

    def get_datasets_base_url(self, workpsace_id=None):
        GROUP_DATASETS_API=analyticsMap.get(self.dc)+"/restapi/v2/workspaces/{group_id}/views"
        ret = GROUP_DATASETS_API.format(group_id=workpsace_id)
        return ret

    def get(self, url, custom_error_messages=None):
        response = requests.get(url, headers=self.headers)
        assert_response_ok(response, custom_error_messages=custom_error_messages)
        json_response = response.json()
        return json_response

    def post(self, url, data, fail_on_errors=True):
        headers_dup=self.headers
        headers_dup["Content-Type"]="application/x-www-form-urlencoded"
        response = requests.post(
            url,
            data=data,
            headers=headers_dup
        )
        assert_response_ok(response, fail_on_errors=fail_on_errors)
        if is_json_response(response):
            return response.json()
        else:
            return response

    def _delete(self, url, fail_on_errors=True):
        response = requests.delete(
            url,
            headers=self.headers
        )
        assert_response_ok(response, fail_on_errors=fail_on_errors)
        if is_json_response(response):
            return response.json()
        else:
            return response

    def post_table_row(self, rows, dsid, export_method,table="ExportFromDSS", workpsace_id=None,column_name=None):
        payload = {}
        new_data = self.json_filter(rows)
        if export_method == "new_dataset":
            export_method="append"
        payload["DATA"]=new_data
        logger.info(export_method)
        config=json.dumps({"importType": ""+export_method,"fileType": "json","autoIdentify": "true", "dateFormat":"yyyy-MM-dd HH:mm:ss"})
        if export_method == "updateadd":
            config=json.dumps({"importType": ""+export_method,"fileType": "json","autoIdentify": "true", "dateFormat":"yyyy-MM-dd HH:mm:ss","matchingColumns":column_name})
        payload["CONFIG"]=config
        logger.info(payload)
        TABLE_ROWS_API=analyticsMap.get(self.dc)+"/restapi/v2/workspaces/{}/views/{}/data"
        response = self.post(TABLE_ROWS_API.format(workpsace_id,dsid),
            data=payload,
            fail_on_errors=True
        )
        return response

    def parse_formattable_values(self, rows):
        ret = []
        try:
            for row in rows:
                for column_with_date in self.columns_with_date:
                    date_to_convert = row[column_with_date]
                    row[column_with_date] = date_convertion(date_to_convert)
                for column_with_boolean in self.columns_with_boolean:
                    boolean_to_check = row[column_with_boolean]
                    row[column_with_boolean] = boolean_check(boolean_to_check)
                for cols in self.columns:
                    valueTocheck= row[cols]
                    row[cols] = is_nan(valueTocheck)
                ret.append(row)
        except AttributeError:
            raise Exception("Date '{}' is not correctly formatted".format(date_to_convert))
        return json.dumps(ret)


def date_convertion(pandas_date):
    ret = pandas_date.isoformat()
    if ret == "NaT":
        ret = None
    return ret


def boolean_check(pandas_boolean):
    if math.isnan(pandas_boolean):
        return None
    else:
        return pandas_boolean

def is_nan(valueTocheck):
    if pd.isnan(valueTocheck):
        return ""
    else:
        return valueTocheck

def is_json_response(response):
    return response.headers.get('content-type').find("application/json") >= 0


def assert_response_ok(response,while_trying=None, fail_on_errors=True, custom_error_messages=None):
    if response.status_code >= 400:
        error_message = get_error_message(response, while_trying=while_trying, custom_error_messages=custom_error_messages)
        error_message = error_message
        handle_exception_message(error_message, fail_on_errors=fail_on_errors)


def handle_exception_message(message, fail_on_errors=True):
    if fail_on_errors:
        raise Exception(message)
    else:
        logger.error(message)


def get_error_message(response, while_trying=None, custom_error_messages=None):
    custom_error_messages = custom_error_messages or {}
    error_message = ""
    if custom_error_messages and (response.status_code in custom_error_messages):
        error_message = custom_error_messages.get(response.status_code, "")
    elif while_trying is None:
        response_message = extract_error_message_from_response(response)
        error_message = "Error {}: {}".format(response.status_code, response_message)
    else:
        error_message = "Error {} while {}: {}".format(response.status_code, while_trying, response.content)
    return error_message


def extract_error_message_from_response(response):
    ret = ""
    try:
        json_response = response.json()
        ret = get_value_from_path(json_response, ["error", "message"], response.content)
    except Exception:
        ret = response.content
    return ret


def get_value_from_path(dictionary, path, default_reply=None):
    ret = dictionary
    for key in path:
        if key in ret:
            ret = ret.get(key)
        else:
            return default_reply
    return ret


def generate_access_token(refreshtoken=None, client_id=None, client_secret=None,dc="US"):
    data = {
        "refresh_token": refreshtoken,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "refresh_token"
    }
    response = requests.post(accountsMap.get(dc)+'/oauth/v2/token', data=data)
    assert_response_ok(response, while_trying="retrieving access token")
    return response.json()
