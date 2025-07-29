import pandas as pd

# Mapping dictionaries for each data type

CDR_COLUMN_MAP = {
    "cdr_id": ["cdrid", "cdr_id"],
    "calling_number": ["callingnumber", "caller", "msisdn"],
    "called_number": ["callednumber", "callee", "dst"],
    "imsi": ["imsi"],
    "imei": ["imei"],
    "start_time": ["start_time", "starttime", "timestamp"],
    "end_time": ["end_time", "endtime", "end"],
    "duration_seconds": ["duration_seconds", "duration", "callduration"],
    "call_type": ["calltype", "call_type"],
    "call_direction": ["direction", "call_direction"],
    "call_status": ["status", "call_status"],
    "tower_id": ["towerid", "tower_id"],
    "lac": ["lac"],
    "cell_id": ["cellid", "cell_id"],
    "latitude": ["latitude", "lat"],
    "longitude": ["longitude", "lon"],
    "city": ["city", "city_name"],
    "network_type": ["networktype", "network_type"],
    "roaming_status": ["roamingstatus", "roaming_status"],
    "operator": ["operator", "operator_name"],
    "billing_type": ["billingtype", "billing_type"],
    "charge_amount": ["charge", "charge_amount"],
}

IPDR_COLUMN_MAP = {
    "subscriber_id": ["subscriberid", "subscriber_id"],
    "user_id": ["userid", "user_id"],
    "protocol": ["protocol"],
    "src_ip": ["sourceip", "srcip", "ip_src"],
    "src_port": ["sourceport", "srcport", "port_src"],
    "post_nat_source_ip": ["postnatsourceip", "postnatsrcip", "post_nat_src_ip", "post_nat_ip"],
    "post_nat_source_port": ["postnatsourceport", "postnatsrcport", "post_nat_src_port"],
    "dest_ip": ["destinationip", "dstip", "ip_dst"],
    "dest_port": ["destinationport", "dstport", "port_dst"],
    "timestamp": ["timestamp", "datetime", "event_time"],
    "flow_start_time": ["flowstarttime", "flow_start_time", "session_start"],
    "flow_end_time": ["flowendtime", "flow_end_time", "session_end"],
    "bytes_sent": ["bytessent", "outbytes", "bytes_sent"],
    "bytes_received": ["bytesreceived", "inbytes", "bytes_received"],
    "session_id": ["sessionid", "session_id"],
}

FIREWALL_COLUMN_MAP = {
    "timestamp": ["receive time", "generated time", "starttime", "timestamp"],
    "src_ip": ["source address", "srcip", "src_ip"],
    "dst_ip": ["destination address", "dstip", "dst_ip"],
    "src_port": ["source port", "srcport", "src_port"],
    "dst_port": ["destination port", "dstport", "dst_port"],
    "protocol": ["protocol", "ip protocol"],
    "action": ["action"],
    "application": ["application", "app"],
    "bytes_sent": ["bytes sent", "outbytes", "bytes_sent", "bytes"],
    "bytes_received": ["bytes received", "inbytes", "bytes_received"],
    "bytes": ["bytes", "outbytes"],
    "duration": ["duration"],
    "user_id": ["userid", "user_id"],
    "device_id": ["deviceid", "device_id"],
    "country": ["country"],
    "session_id": ["session id", "sessionid", "session_id"],
    "threat_type": ["threattype", "threat_type"],
    "rule_name": ["rule name", "rule_name"],
    "src_mac": [
        "source mac", "srcmac", "src_mac", "source mac address", "mac address", 
        "client mac", "hardware address", "source hw address"
    ],
}

GEOIP_COLUMN_MAP = {
    "ip": ["ip", "ip_address"],
    "country": ["country", "country_name"],
    "country_code": ["countrycode", "country_iso_code"],
    "region": ["region", "region_name"],
    "region_code": ["regioncode", "region_iso_code"],
    "city": ["city", "city_name"],
    "latitude": ["latitude", "lat"],
    "longitude": ["longitude", "lon"],
    "postal_code": ["postalcode", "postal_code"],
    "timezone": ["timezone", "time_zone"],
    "asn": ["asn", "as_number"],
    "organization": ["organization", "org_name"],
    "isp": ["isp", "isp_name"],
    "timestamp": ["timestamp"],
}

DNS_COLUMN_MAP = {
    "timestamp": ["timestamp", "start_time"],
    "client_ip": ["sourceip", "client_ip"],
    "query_name": ["queryname", "qname"],
    "query_type": ["querytype", "qtype"],
    "response_code": ["responsecode", "rcode"],
    "response_cached": ["responsecached"],
    "server_ip": ["serverip", "servers.ip"],
    "latency": ["latency", "latency_mean"],
    "answer_ip": ["answer_ip", "answers", "response", "answer"],
}

WHOIS_COLUMN_MAP = {
    "lookup_time": ["lookuptime", "lookup_time"],
    "domain_name": ["domain name", "domain"],
    "domain": ["domain", "domain_name"],
    "registrar": ["registrar"],
    "registrant_name": ["registrant name", "owner"],
    "registrant_org": ["registrant organization"],
    "registrant_email": ["registrant email"],
    "registrant_phone": ["registrant phone"],
    "registrant_country": ["registrant country", "registrant_country"],
    "privacy_protected": ["privacyprotected", "privacy_protected"],
    "privacy_provider": ["privacyprovider", "privacy_provider"],
    "creation_date": ["creation date", "created"],
    "registration_date": ["registrationdate", "registration_date"],
    "expiration_date": ["expiry date", "expires"],
    "expiry_date": ["expirydate", "expiry_date"],
    "updated_date": ["updated date", "last_updated"],
    "nameservers": ["nameservers", "ns1", "ns2"],
    "status": ["status", "domain_status"],
}

# Normalizing function

def _normalize_columns(df, column_map):
    col_rename = {}
    df_cols = {col.lower().replace(" ", "").replace("_", ""): col for col in df.columns}
    for std_col, variants in column_map.items():
        for variant in variants:
            key = variant.lower().replace(" ", "").replace("_", "")
            if key in df_cols:
                col_rename[df_cols[key]] = std_col
                break
    return df.rename(columns=col_rename)

# Parsing functions

def parse_cdr(df):
    return _normalize_columns(df, CDR_COLUMN_MAP)

def parse_ipdr(df):
    return _normalize_columns(df, IPDR_COLUMN_MAP)

def parse_firewall_log(df):
    return _normalize_columns(df, FIREWALL_COLUMN_MAP)

def parse_geoip(df):
    return _normalize_columns(df, GEOIP_COLUMN_MAP)

def parse_dns_log(df):
    return _normalize_columns(df, DNS_COLUMN_MAP)

def parse_whois(df):
    return _normalize_columns(df, WHOIS_COLUMN_MAP)