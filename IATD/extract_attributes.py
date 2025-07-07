import pandas as pd


ATTRIBUTES = [
    'timestamp',
    'src_ip', 'dst_ip', 'protocol', 'ttl', 'ip_len',
    'ip_flag_df', 'ip_flag_mf', 'ip_flag_rb',
    'src_port', 'dst_port',
    'tcp_flag_res', 'tcp_flag_ns', 'tcp_flag_cwr', 'tcp_flag_ecn',
    'tcp_flag_urg', 'tcp_flag_ack', 'tcp_flag_push',
    'tcp_flag_reset', 'tcp_flag_syn', 'tcp_flag_fin',
    'mqtt_messagetype', 'mqtt_messagelength',
    'mqtt_flag_uname', 'mqtt_flag_passwd', 'mqtt_flag_retain',
    'mqtt_flag_qos', 'mqtt_flag_willflag', 'mqtt_flag_clean',
    'mqtt_flag_reserved',
    'is_attack'
]

IP_ATTACKER = '192.168.100.5'


def convert2int(flag):
    if str(flag).lower() == 'true':  return 1
    elif str(flag).lower() == 'false':  return 0
    return flag

def process_packet(packet):

    layer = packet["layers"]

    packet_features = {attribute: '' for attribute in ATTRIBUTES}
    packet_features['timestamp'] = layer.get("frame", {}).get("frame_frame_time")
    packet_features['protocol'] = layer.get("frame", {}).get("frame_frame_protocols", "").split(":")[-1]

    layer_ip = layer.get("ip", {})
    layer_tcp = layer.get("tcp", {})
    layer_mqtt = layer.get("mqtt", {})

    if layer_ip:
        packet_features['src_ip'] = layer_ip.get('ip_ip_src', '')
        packet_features['dst_ip'] = layer_ip.get('ip_ip_dst', '')
        packet_features['ttl'] = layer_ip.get('ip_ip_ttl', '')
        packet_features['ip_len'] = layer_ip.get('ip_ip_len', '')

        packet_features['ip_flag_df'] = convert2int(layer_ip.get('ip_ip_flags_df', ''))
        packet_features['ip_flag_mf'] = convert2int(layer_ip.get('ip_ip_flags_mf', ''))
        packet_features['ip_flag_rb'] = convert2int(layer_ip.get('ip_ip_flags_rb', ''))

        if (packet_features['src_ip'] == IP_ATTACKER or packet_features['dst_ip'] == IP_ATTACKER):
            packet_features['is_attack'] = 1
        else:
            packet_features['is_attack'] = 0

    else:  packet_features['is_attack'] = 0

    if layer_tcp:
        packet_features['src_port'] = layer_tcp.get('tcp_tcp_srcport', '')
        packet_features['dst_port'] = layer_tcp.get('tcp_tcp_dstport', '')

        packet_features['tcp_flag_res'] = convert2int(layer_tcp.get('tcp_tcp_flags_res', ''))
        packet_features['tcp_flag_ns'] = convert2int(layer_tcp.get('tcp_tcp_flags_ns', ''))
        packet_features['tcp_flag_cwr'] = convert2int(layer_tcp.get('tcp_tcp_flags_cwr', ''))
        packet_features['tcp_flag_ecn'] = convert2int(layer_tcp.get('tcp_tcp_flags_ecn', ''))
        packet_features['tcp_flag_urg'] = convert2int(layer_tcp.get('tcp_tcp_flags_urg', ''))
        packet_features['tcp_flag_ack'] = convert2int(layer_tcp.get('tcp_tcp_flags_ack', ''))
        packet_features['tcp_flag_push'] = convert2int(layer_tcp.get('tcp_tcp_flags_push', ''))
        packet_features['tcp_flag_reset'] = convert2int(layer_tcp.get('tcp_tcp_flags_reset', ''))
        packet_features['tcp_flag_syn'] = convert2int(layer_tcp.get('tcp_tcp_flags_syn', ''))
        packet_features['tcp_flag_fin'] = convert2int(layer_tcp.get('tcp_tcp_flags_fin', ''))

    else:
        layer_udp = layer.get("udp", {})
        if layer_udp:
            packet_features['src_port'] = layer_udp.get('udp_udp_srcport', '')
            packet_features['dst_port'] = layer_udp.get('udp_udp_dstport', '')

    if layer_mqtt:
        packet_features['mqtt_messagetype'] = layer_mqtt.get('mqtt_mqtt_msgtype', '')
        packet_features['mqtt_messagelength'] = layer_mqtt.get('mqtt_mqtt_len', '')

        packet_features['mqtt_flag_uname'] = convert2int(layer_mqtt.get('mqtt_mqtt_conflag_uname', ''))
        packet_features['mqtt_flag_passwd'] = convert2int(layer_mqtt.get('mqtt_mqtt_conflag_passwd', ''))
        packet_features['mqtt_flag_retain'] = convert2int(layer_mqtt.get('mqtt_mqtt_conflag_retain', ''))
        packet_features['mqtt_flag_qos'] = convert2int(layer_mqtt.get('mqtt_mqtt_conflag_qos', ''))
        packet_features['mqtt_flag_willflag'] = convert2int(layer_mqtt.get('mqtt_mqtt_conflag_willflag', ''))
        packet_features['mqtt_flag_clean'] = convert2int(layer_mqtt.get('mqtt_mqtt_conflag_cleansess', ''))
        packet_features['mqtt_flag_clean'] = convert2int(layer_mqtt.get('mqtt_mqtt_conflag_reserved', ''))

    df_packet_features = pd.DataFrame([packet_features])
    return df_packet_features
