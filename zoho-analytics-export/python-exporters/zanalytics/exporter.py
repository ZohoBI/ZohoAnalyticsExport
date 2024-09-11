import json
from zohoanalytics import ZohoAnalytics, generate_access_token,analyticsMap
from dataiku.exporter import Exporter
from math import isnan
from safe_logger import SafeLogger


logger = SafeLogger("zohoanalyticsexport plugin", forbiden_keys=["client-id", "refreshtoken", "client-secret"])




class ZohoAnalyticsExporter(Exporter):

    EMPTY_CONNECTION = {"username": None, "password": None, "client-id": None, "client-secret": None}

    def __init__(self, config, plugin_config):
        logger.info("config={}, plugin_config={}".format(logger.filter_secrets(config), logger.filter_secrets(plugin_config)))
        self.config = config
        self.plugin_config = plugin_config
        self.row_index = 0
        self.row_buffer = {}
        self.row_buffer["rows"] = []
        self.table_id= None
        self.workspace_name = self.config.get("dataset", None)

        self.table = self.config.get("dataset", None)
        self.buffer_size = self.config.get("buffer_size", None)

        self.export_method = self.config.get("export_method", None)

        authentication_method = self.config.get("authentication_method", None)
        zanalytics_connection = self.config.get("zanalytics_connection", self.EMPTY_CONNECTION)
        self.refreshtoken = zanalytics_connection.get("refreshtoken", None)
        self.client_id = zanalytics_connection.get("client-id", None)
        self.client_secret = zanalytics_connection.get("client-secret", None)
        self.org_id=self.config.get("org_id",None)
        self.dc=zanalytics_connection.get("dc",None)
        # Retrieve access token
        response = generate_access_token(
                self.refreshtoken,
                self.client_id,
                self.client_secret
        )
        token = response.get("access_token")
        if token is None:
            logger.error("ERROR [-] Error while retrieving your Zoho Analytics access token, please check your credentials.")
            logger.error("ERROR [-] Zoho authentication API response:")
            logger.error(json.dumps(response, indent=4))
            raise Exception("Authentication error")
        self.column_name=None
        self.za = ZohoAnalytics(token,self.org_id,self.dc)
        self.workpsace_id = self.config.get("workspace_id",None)
        if self.export_method=="truncateadd" or self.export_method=="append":
            self.table_id=self.config.get("dataset_id",None)
        if self.export_method == "updateadd":
            self.table_id=self.config.get("dataset_id",None)
            self.column_name=self.config.get("column_id",None)
        
    def open(self, schema):
        self.schema = schema
        self.za.register_formattable_columns(self.schema)

        if self.export_method == "truncateadd":
            self.dsid=self.table_id

        elif self.export_method == "append":
            self.dsid=self.table_id
        
        elif self.export_method == "updateadd":
            self.dsid=self.table_id
            
        else:  # new_dataset
            datasets = self.za.get_dataset_by_name(self.workspace_name, workpsace_id=self.workpsace_id)
            if len(datasets) > 0:
                logger.error("ERROR [-] Dataset with name {} already exists".format(self.workspace_name))
                raise Exception("Dataset '{}' already exists".format(self.workspace_name))
            response = self.za.create_dataset_from_schema(
                    workspace_name=self.workspace_name,
                    table=self.table,
                    workpsace_id=self.workpsace_id,
                    schema=schema
            )
            if response.get("data").get("viewId") is None:
                logger.error("ERROR [-] Error while creating your Zoho Analytics table.")
                logger.error("ERROR [-] Zoho response:")
                logger.error(json.dumps(response, indent=4))
                raise Exception("Dataset creation error probably from Zoho Analytics")

            self.dsid = response["data"]["viewId"]
            logger.info("[+] Created new Zoho Analytics Table ID {}".format(self.dsid))

    def write_row(self, row):
        row_obj = {}
        for (col, val) in zip(self.schema["columns"], row):
            if col['type'] in ['int', 'bigint', 'tinyint', 'smallint']:
                row_obj[col["name"]] = int(val) if val is not None and not isnan(val) else None
            else:
                row_obj[col["name"]] = val 
        self.row_buffer["rows"].append(row_obj)
        if len(self.row_buffer["rows"]) > self.buffer_size:
            self.za.post_table_row(
                self.row_buffer["rows"],
                self.dsid,
                self.export_method,
                self.table,
                self.workpsace_id,self.column_name
            )
            self.row_buffer["rows"] = []
        self.row_index += 1

    def close(self):
        if len(self.row_buffer["rows"]) > 0:
            self.za.post_table_row(
                self.row_buffer["rows"],
                self.dsid,
                self.export_method,
                self.table,
                self.workpsace_id,self.column_name
            )
        logger.info("[+] Loading complete.")
        msg = ""
        msg = msg + "[+] {}".format("="*80) + "\n"
        msg = msg + "[+] Your Zoho Analytics Table should be available at:" + "\n"
        msg = msg + "[+] "+analyticsMap.get(self.dc)+"/workspace/"+self.workpsace_id +"/view/"+self.dsid+"\n"
        msg = msg + "[+] {}".format("="*80)
        logger.info(msg)
