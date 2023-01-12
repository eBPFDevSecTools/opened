TXL_STRUCT_DICT:
dict_keys(['is_under_flood', 'get_packet_dst', 'connection_table_lookup', 'process_l3_headers', 'check_decap_dst', 'reals_have_same_addr', 'perform_global_lru_lookup', 'process_encaped_ipip_pckt', 'process_encaped_gue_pckt', 'increment_quic_cid_version_stats', 'increment_quic_cid_drop_no_real', 'increment_quic_cid_drop_real_0', 'process_packet', 'balancer_ingress', 'get_packet_hash', 'xdpdecap', 'xdp_prog_simple', 'xdp_root', 'xdp_val', 'healthcheck_encap', 'pktcntr', 'encap_v6', 'encap_v4', 'decap_v6', 'decap_v4', 'gue_csum', 'gue_encap_v4', 'gue_encap_v6', 'gue_decap_v4', 'gue_decap_v6', 'set_hc_key', 'hc_encap_ipip', 'gue_sport', 'hc_encap_gue', 'create_v4_hdr', 'create_v6_hdr', 'create_udp_hdr', 'rol32', 'jhash', '__jhash_nwords', 'jhash_2words', 'jhash_1word', 'submit_event', 'recirculate', 'decrement_ttl', 'calc_offset', 'parse_udp', 'parse_tcp', 'parse_hdr_opt', 'tcp_hdr_opt_lookup', 'parse_quic', 'get_next_ports', 'gue_record_route', 'csum_fold_helper', 'min_helper', 'ipv4_csum', 'ipv4_csum_inline', 'ipv4_l4_csum', 'ipv6_csum', 'add_pseudo_ipv6_header', 'rem_pseudo_ipv6_header', 'add_pseudo_ipv4_header', 'rem_pseudo_ipv4_header', 'gue_csum_v6', 'gue_csum_v4', 'gue_csum_v4_in_v6', 'swap_mac_and_send', 'swap_mac', 'send_icmp_reply', 'send_icmp6_reply', 'send_icmp4_too_big', 'send_icmp6_too_big', 'send_icmp_too_big', 'parse_icmpv6', 'parse_icmp'])
python3 src/extraction_runner.py -f is_under_flood -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f get_packet_dst -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f connection_table_lookup -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f process_l3_headers -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f process_l3_headers -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f check_decap_dst -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f reals_have_same_addr -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f perform_global_lru_lookup -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f process_encaped_ipip_pckt -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f process_encaped_ipip_pckt -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f process_encaped_gue_pckt -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f process_encaped_gue_pckt -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f increment_quic_cid_version_stats -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f increment_quic_cid_drop_no_real -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f increment_quic_cid_drop_real_0 -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f process_packet -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f process_packet -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f balancer_ingress -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f get_packet_hash -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f xdpdecap -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f xdp_prog_simple -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f xdp_root -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f xdp_val -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f healthcheck_encap -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f healthcheck_encap -d cilium.db -g op/fcg  -r cilium
python3 src/extraction_runner.py -f pktcntr -d cilium.db -g op/fcg  -r cilium
#Skipping: encap_v6 in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: encap_v4 in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: decap_v6 in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: decap_v4 in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: gue_csum in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: gue_encap_v4 in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: gue_encap_v6 in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: gue_decap_v4 in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: gue_decap_v6 in /home/sayandes/opened_extraction/examples/katran/pckt_encap.h
#Skipping: set_hc_key in /home/sayandes/opened_extraction/examples/katran/healthchecking_helpers.h
#Skipping: hc_encap_ipip in /home/sayandes/opened_extraction/examples/katran/healthchecking_helpers.h
#Skipping: gue_sport in /home/sayandes/opened_extraction/examples/katran/healthchecking_helpers.h
#Skipping: hc_encap_gue in /home/sayandes/opened_extraction/examples/katran/healthchecking_helpers.h
#Skipping: create_v4_hdr in /home/sayandes/opened_extraction/examples/katran/encap_helpers.h
#Skipping: create_v6_hdr in /home/sayandes/opened_extraction/examples/katran/encap_helpers.h
#Skipping: create_udp_hdr in /home/sayandes/opened_extraction/examples/katran/encap_helpers.h
#Skipping: rol32 in /home/sayandes/opened_extraction/examples/katran/jhash.h
#Skipping: jhash in /home/sayandes/opened_extraction/examples/katran/jhash.h
#Skipping: __jhash_nwords in /home/sayandes/opened_extraction/examples/katran/jhash.h
#Skipping: jhash_2words in /home/sayandes/opened_extraction/examples/katran/jhash.h
#Skipping: jhash_1word in /home/sayandes/opened_extraction/examples/katran/jhash.h
#Skipping: submit_event in /home/sayandes/opened_extraction/examples/katran/balancer_helpers.h
#Skipping: recirculate in /home/sayandes/opened_extraction/examples/katran/balancer_helpers.h
#Skipping: decrement_ttl in /home/sayandes/opened_extraction/examples/katran/balancer_helpers.h
#Skipping: calc_offset in /home/sayandes/opened_extraction/examples/katran/pckt_parsing.h
#Skipping: parse_udp in /home/sayandes/opened_extraction/examples/katran/pckt_parsing.h
#Skipping: parse_tcp in /home/sayandes/opened_extraction/examples/katran/pckt_parsing.h
#Skipping: parse_hdr_opt in /home/sayandes/opened_extraction/examples/katran/pckt_parsing.h
#Skipping: tcp_hdr_opt_lookup in /home/sayandes/opened_extraction/examples/katran/pckt_parsing.h
#Skipping: parse_quic in /home/sayandes/opened_extraction/examples/katran/pckt_parsing.h
#Skipping: get_next_ports in /home/sayandes/opened_extraction/examples/katran/flow_debug_helpers.h
#Skipping: gue_record_route in /home/sayandes/opened_extraction/examples/katran/flow_debug_helpers.h
#Skipping: csum_fold_helper in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: min_helper in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: ipv4_csum in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: ipv4_csum_inline in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: ipv4_l4_csum in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: ipv6_csum in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: add_pseudo_ipv6_header in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: rem_pseudo_ipv6_header in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: add_pseudo_ipv4_header in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: rem_pseudo_ipv4_header in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: gue_csum_v6 in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: gue_csum_v4 in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: gue_csum_v4_in_v6 in /home/sayandes/opened_extraction/examples/katran/csum_helpers.h
#Skipping: swap_mac_and_send in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
#Skipping: swap_mac in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
#Skipping: send_icmp_reply in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
#Skipping: send_icmp6_reply in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
#Skipping: send_icmp4_too_big in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
#Skipping: send_icmp6_too_big in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
#Skipping: send_icmp_too_big in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
#Skipping: parse_icmpv6 in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
#Skipping: parse_icmp in /home/sayandes/opened_extraction/examples/katran/handle_icmp.h
