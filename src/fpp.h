/*
*   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
*   Copyright 2016 NXP
*
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*
*/

#ifndef __FPP__
#define __FPP__

#include <pcap-bpf.h>
#include <pcap.h>
#ifndef IFNAMSIZ
#define IFNAMSIZ	16
#endif

/*Actions used in severals commands*/
#define FPP_ACTION_REGISTER                             0
#define FPP_ACTION_DEREGISTER                           1
#define FPP_ACTION_KEEP_ALIVE                           2
#define FPP_ACTION_REMOVED                              3
#define FPP_ACTION_UPDATE                               4
#define FPP_ACTION_QUERY                                6
#define FPP_ACTION_QUERY_CONT                           7
#define FPP_ACTION_QUERY_LOCAL                          8
#define FPP_ACTION_TCP_FIN                              9

/* !!!!!!!!!!!!!  NOTE: PLEASE SYNC PFE ERROR LIST ON UPDATE  !!!!!!!!!!!!!!! */
/*-------------------------------- General -----------------------------------*/
#define FPP_ERR_OK                                      0
#define FPP_ERR_UNKNOWN_COMMAND                         1
#define FPP_ERR_WRONG_COMMAND_SIZE                      2
#define FPP_ERR_WRONG_COMMAND_PARAM                     3

#define FPP_ERR_UNKNOWN_ACTION                          4
#define FPP_ERR_UNKNOWN_INTERFACE                       5
#define FPP_ERR_NOT_ENOUGH_MEMORY                       6
#define FPP_ERR_CREATION_FAILED                         7
#define FPP_ERR_WRONG_PARAM_VALUE                       8
#define FPP_ERR_PARAM_VALUE_OUT_OF_RANGE                9

/*-------------------------------- RX Module ---------------------------------*/
#define FPP_ERR_BRIDGE_ENTRY_NOT_FOUND                  50
#define FPP_ERR_BRIDGE_ENTRY_ALREADY_EXISTS             51
#define FPP_ERR_BRIDGE_WRONG_MODE                       52

/*-------------------------------- MacVlan -----------------------------------*/
#define FPP_ERR_MACVLAN_ENTRY_ALREADY_REGISTERED        60
#define FPP_ERR_MACVLAN_ENTRY_NOT_FOUND                 61
#define FPP_ERR_MACVLAN_ENTRY_INVALID                   62

/*-------------------------------- Conntrack ---------------------------------*/
#define FPP_ERR_CT_ENTRY_ALREADY_REGISTERED             100
#define FPP_ERR_CT_ENTRY_NOT_FOUND                      101
#define FPP_ERR_CT_ENTRY_INVALID_SA                     102
#define FPP_ERR_CT_ENTRY_TOO_MANY_SA_OP                 103

/*-------------------------------- IP ----------------------------------------*/ 
#define FPP_ERR_RT_ENTRY_ALREADY_REGISTERED             200
#define FPP_ERR_RT_ENTRY_NOT_FOUND                      201
#define FPP_ERR_RT_ENTRY_LINKED                         202
#define FPP_ERR_RT_LINK_NOT_POSSIBLE                    203

/*-------------------------------- QOS ---------------------------------------*/
#define FPP_ERR_QM_QUEUE_RATE_LIMITED                   500
#define FPP_ERR_QM_RATE_LIMIT_NOT_APPLIED_TO_OFF        501
#define FPP_ERR_QM_QUEUE_OUT_OF_RANGE                   502
#define FPP_ERR_QM_NUM_DSCP_OUT_OF_RANGE                503
#define FPP_ERR_QM_DSCP_OUT_OF_RANGE                    504
#define FPP_ERR_QM_NO_FREE_SHAPER                       505
#define FPP_ERR_QM_NO_QUEUE_SPECIFIED                   506

/*-------------------------------- VLAN --------------------------------------*/
#define FPP_ERR_VLAN_ENTRY_ALREADY_REGISTERED           600
#define FPP_ERR_VLAN_ENTRY_NOT_FOUND                    601

/*-------------------------------- Multicast ---------------------------------*/
#define FPP_ERR_MC_ENTRY_NOT_FOUND                      700
#define FPP_ERR_MC_MAX_LISTENERS                        701
#define FPP_ERR_MC_DUP_LISTENER                         702
#define FPP_ERR_MC_ENTRY_OVERLAP                        703
#define FPP_ERR_MC_INVALID_ADDR                         704
#define FPP_ERR_MC_INTERFACE_NOT_ALLOWED                705

/*-------------------------------- PPPoE -------------------------------------*/
#define FPP_ERR_PPPOE_ENTRY_ALREADY_REGISTERED          800
#define FPP_ERR_PPPOE_ENTRY_NOT_FOUND                   801

/*-------------------------------- IPSec -------------------------------------*/
#define FPP_ERR_SA_DUPLICATED                           904
#define FPP_ERR_SA_DUPLICATED_HANDLE                    905
#define FPP_ERR_SA_UNKNOWN                              906
#define FPP_ERR_SA_INVALID_CIPHER_KEY                   907
#define FPP_ERR_SA_INVALID_DIGEST_KEY                   908
#define FPP_ERR_SA_ENTRY_NOT_FOUND                      909
#define FPP_ERR_SA_SOCK_ENTRY_NOT_FOUND                 910
#define FPP_ERR_SA_INVALID_MODE                         911

/*-------------------------------- Tunnels -----------------------------------*/
#define FPP_ERR_TNL_MAX_ENTRIES                         1000
#define FPP_ERR_TNL_ENTRY_NOT_FOUND                     1001
#define FPP_ERR_TNL_NOT_SUPPORTED                       1002
#define FPP_ERR_TNL_NO_FREE_ENTRY                       1003
#define FPP_ERR_TNL_ALREADY_CREATED                     1004

/*-------------------------------- Stat --------------------------------------*/
#define FPP_ERR_STAT_FEATURE_NOT_ENABLED                1100

/*-------------------------------- Exceptions --------------------------------*/
#define FPP_ERR_EXPT_QUEUE_OUT_OF_RANGE                 1101
#define FPP_ERR_EXPT_NUM_DSCP_OUT_OF_RANGE              1102
#define FPP_ERR_EXPT_DSCP_OUT_OF_RANGE                  1103

/*-------------------------------- Sockets -----------------------------------*/
#define FPP_ERR_SOCK_ALREADY_OPEN                       1200
#define FPP_ERR_SOCKID_ALREADY_USED                     1201
#define FPP_ERR_SOCK_ALREADY_OPENED_WITH_OTHER_ID       1202
#define FPP_ERR_TOO_MANY_SOCKET_OPEN                    1203
#define FPP_ERR_SOCKID_UNKNOWN                          1204
#define FPP_ERR_SOCK_ALREADY_IN_USE                     1206
#define FPP_ERR_RTP_CALLID_IN_USE                       1207
#define FPP_ERR_RTP_UNKNOWN_CALL                        1208
#define FPP_ERR_WRONG_SOCKID                            1209
#define FPP_ERR_RTP_SPECIAL_PKT_LEN                     1210
#define FPP_ERR_RTP_CALL_TABLE_FULL                     1211
#define FPP_ERR_WRONG_SOCK_FAMILY                       1212
#define FPP_ERR_WRONG_SOCK_PROTO                        1213
#define FPP_ERR_WRONG_SOCK_TYPE                         1214
#define FPP_ERR_MSP_NOT_READY                           1215
#define FPP_ERR_WRONG_SOCK_MODE                         1216
#if defined (LS1043)
#define FPP_ERR_NO_ROUTE_TO_SOCK						1217
#define FPP_ERR_SOCK_UPDATE_ERR							1218
#endif //LS1043

/* ------------------------------- NATPT -------------------------------------*/
#define FPP_ERR_NATPT_UNKNOWN_CONNECTION                1220

/* ------------------------------- RTP ---------------------------------------*/
#define FPP_ERR_RTP_STATS_MAX_ENTRIES                   1230
#define FPP_ERR_RTP_STATS_STREAMID_ALREADY_USED         1231 
#define FPP_ERR_RTP_STATS_STREAMID_UNKNOWN              1232
#define FPP_ERR_RTP_STATS_DUPLICATED                    1233
#define FPP_ERR_RTP_STATS_WRONG_DTMF_PT                 1234
#define FPP_ERR_RTP_STATS_WRONG_TYPE                    1235
#define FPP_ERR_RTP_STATS_NOT_AVAILABLE                 1236

/*-------------------------------- Voice Buffer ------------------------------*/
#define FPP_ERR_VOICE_BUFFER_UNKNOWN                    1240
#define FPP_ERR_VOICE_BUFFER_USED                       1241
#define FPP_ERR_VOICE_BUFFER_PT                         1242
#define FPP_ERR_VOICE_BUFFER_FRAME_SIZE                 1243
#define FPP_ERR_VOICE_BUFFER_ENTRIES                    1244
#define FPP_ERR_VOICE_BUFFER_SIZE                       1245
#define FPP_ERR_VOICE_BUFFER_STARTED                    1246

/*-------------------------------- Altconf -----------------------------------*/
#define FPP_ERR_ALTCONF_OPTION_NOT_SUPPORTED            1300
#define FPP_ERR_ALTCONF_MODE_NOT_SUPPORTED              1301
#define FPP_ERR_ALTCONF_WRONG_NUM_PARAMS                1302

/*-------------------------------- PKTCAP ------------------------------------*/
#define FPP_ERR_PKTCAP_ALREADY_ENABLED                  1400
#define FPP_ERR_PKTCAP_NOT_ENABLED                      1401
#define FPP_ERR_PKTCAP_FLF_RESET                        1402

/*-------------------------------- ICC ---------------------------------------*/
#define FPP_ERR_ICC_TOO_MANY_ENTRIES                    1500
#define FPP_ERR_ICC_ENTRY_ALREADY_EXISTS                1501
#define FPP_ERR_ICC_ENTRY_NOT_FOUND                     1502
#define FPP_ERR_ICC_THRESHOLD_OUT_OF_RANGE              1503
#define FPP_ERR_ICC_INVALID_MASKLEN                     1504

#define FPP_ERR_FLOW_ENTRY_NOT_FOUND                    1600
#define FPP_ERR_INVALID_IP_FAMILY                       1601

/*-------------------------------- WiFi --------------------------------------*/
#define FPP_ERR_WIFI_DUPLICATE_OPERATION                2001


typedef struct fpp_socket4_open_cmd {
    u_int16_t   id;
    u_int8_t    type;
    u_int8_t    mode;
    u_int32_t   saddr;
    u_int32_t   daddr;
    u_int16_t   sport;
    u_int16_t   dport;
    u_int8_t    proto;
    u_int8_t    queue;
    u_int16_t   dscp;
    u_int32_t   route_id;
#if defined(LS1043)
    u_int16_t       expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
    u_int16_t       rsvd1;
#endif //LS1043
#if defined(COMCERTO_2000) || defined(LS1043)
    u_int16_t   secure;
    u_int16_t   sa_nr_rx;
    u_int16_t   sa_handle_rx[4];
    u_int16_t   sa_nr_tx;
    u_int16_t   sa_handle_tx[4];
    u_int16_t   pad;
#endif
} __attribute__((__packed__)) fpp_socket4_open_cmd_t;

typedef struct fpp_socket4_update_cmd {
    u_int16_t   id;
    u_int16_t   rsvd1;
    u_int32_t   saddr;
    u_int16_t   sport;
    u_int8_t    rsvd2;
    u_int8_t    queue;
    u_int16_t   dscp;
    u_int16_t   pad;
    u_int32_t   route_id;
#if defined(LS1043)
    u_int16_t       expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
    u_int16_t       rsvd3;
#endif //LS1043
#if defined(COMCERTO_2000) || defined(LS1043)
    u_int16_t   secure;
    u_int16_t   sa_nr_rx;
    u_int16_t   sa_handle_rx[4];
    u_int16_t   sa_nr_tx;
    u_int16_t   sa_handle_tx[4];
    u_int16_t pad2;
#endif
} __attribute__((__packed__)) fpp_socket4_update_cmd_t;

typedef struct fpp_socket4_close_cmd {
    u_int16_t   id;
    u_int16_t   pad1;
} __attribute__((__packed__)) fpp_socket4_close_cmd_t;

typedef struct fpp_socket6_open_cmd {
    u_int16_t   id;
    u_int8_t    type;
    u_int8_t    mode;
    u_int32_t   saddr[4];
    u_int32_t   daddr[4];
    u_int16_t   sport;
    u_int16_t   dport;
    u_int8_t    proto;
    u_int8_t    queue;
    u_int16_t   dscp;
    u_int32_t   route_id;
#if defined(LS1043)
    u_int16_t       expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
    u_int16_t       rsvd1;
#endif //LS1043
#if defined(COMCERTO_2000) || defined(LS1043)
    u_int16_t   secure;
    u_int16_t   sa_nr_rx;
    u_int16_t   sa_handle_rx[4];
    u_int16_t   sa_nr_tx;
    u_int16_t   sa_handle_tx[4];
    u_int16_t pad;
#endif
} __attribute__((__packed__)) fpp_socket6_open_cmd_t;

typedef struct fpp_socket6_update_cmd {
    u_int16_t   id;
    u_int16_t   rsvd1;
    u_int32_t   saddr[4];
    u_int16_t   sport;
    u_int8_t    rsvd2;
    u_int8_t    queue;
    u_int16_t   dscp;
    u_int16_t   pad;
    u_int32_t   route_id;
#if defined(LS1043)
    u_int16_t       expt_flag; /* flag use to 1)send first packet to exception path or/and 2)duplicate rtp packets*/
    u_int16_t       rsvd3;
#endif //LS1043
#if defined(COMCERTO_2000) || defined(LS1043)
    u_int16_t   secure;
    u_int16_t   sa_nr_rx;
    u_int16_t   sa_handle_rx[4];
    u_int16_t   sa_nr_tx;
    u_int16_t   sa_handle_tx[4];
    u_int16_t pad2;
#endif
} __attribute__((__packed__)) fpp_socket6_update_cmd_t;

typedef struct fpp_socket6_close_cmd {
    u_int16_t   id;
    u_int16_t   pad1;
} __attribute__((__packed__)) fpp_socket6_close_cmd_t;

/*-------------------------------- Protocols ---------------------------------*/
typedef enum fpp_proto {
    FPP_PROTO_IPV4 = 0,
    FPP_PROTO_IPV6,
    FPP_PROTO_PPPOE,
    FPP_PROTO_MC4,
    FPP_PROTO_MC6
} fpp_proto_t;

/*-------------------------------- Conntrack ---------------------------------*/
#define FPP_CMD_IPV4_CONNTRACK                          0x0314
#define FPP_CMD_IPV6_CONNTRACK                          0x0414

/*Structure representing the command sent to add or remove a Conntrack*/
typedef struct fpp_ct_cmd {
    u_int16_t   action;                       /*Action to perform*/
    u_int16_t   rsvd0;
    u_int32_t   saddr;                        /*Source IP address*/
    u_int32_t   daddr;                        /*Destination IP address*/
    u_int16_t   sport;                        /*Source Port*/
    u_int16_t   dport;                        /*Destination Port*/
    u_int32_t   saddr_reply;
    u_int32_t   daddr_reply;
    u_int16_t   sport_reply;
    u_int16_t   dport_reply;
    u_int16_t   protocol;                     /*TCP, UDP ...*/
    u_int16_t   flags;
    u_int32_t   fwmark;
    u_int32_t   route_id;
    u_int32_t   route_id_reply;
} __attribute__((__packed__)) fpp_ct_cmd_t;

/*Structure representing the command sent to add or remove a Conntrack when extentions (IPsec SA) is available*/
typedef struct fpp_ct_ex_cmd {
    u_int16_t   action;                     /*Action to perform*/
    u_int16_t   format;                     /* bit 0 : indicates if SA info are present in command */
                                            /* bit 1 : indicates if orig Route info is present in command  */
                                            /* bit 2 : indicates if repl Route info is present in command  */
    u_int32_t   saddr;                      /*Source IP address*/
    u_int32_t   daddr;                      /*Destination IP address*/
    u_int16_t   sport;                      /*Source Port*/
    u_int16_t   dport;                      /*Destination Port*/
    u_int32_t   saddr_reply;
    u_int32_t   daddr_reply;
    u_int16_t   sport_reply;
    u_int16_t   dport_reply;
    u_int16_t   protocol;                   /*TCP, UDP ...*/
    u_int16_t   flags;
    u_int32_t   fwmark;
    u_int32_t   route_id;
    u_int32_t   route_id_reply;
    // optional security parameters
    u_int8_t    sa_dir;
    u_int8_t    sa_nr;
    u_int16_t   sa_handle[4];
    u_int8_t    sa_reply_dir;
    u_int8_t    sa_reply_nr;
    u_int16_t   sa_reply_handle[4];
    u_int32_t   tunnel_route_id;
    u_int32_t   tunnel_route_id_reply;
} __attribute__((__packed__)) fpp_ct_ex_cmd_t;

typedef struct fpp_ct6_cmd {
    u_int16_t   action;                       /*Action to perform*/
    u_int16_t    rsvd1;
    u_int32_t   saddr[4];                     /*Source IP address*/
    u_int32_t   daddr[4];                     /*Destination IP address*/
    u_int16_t   sport;                        /*Source Port*/
    u_int16_t   dport;                        /*Destination Port*/
    u_int32_t   saddr_reply[4];
    u_int32_t   daddr_reply[4];
    u_int16_t   sport_reply;
    u_int16_t   dport_reply;
    u_int16_t   protocol;                     /*TCP, UDP ...*/
    u_int16_t   flags;
    u_int32_t   fwmark;
    u_int32_t   route_id;
    u_int32_t   route_id_reply;
} __attribute__((__packed__)) fpp_ct6_cmd_t;

typedef struct fpp_ct6_ex_cmd {
    u_int16_t   action;                       /*Action to perform*/
    u_int16_t   format;                       /* indicates if SA info are present in command */
    u_int32_t   saddr[4];                     /*Source IP address*/
    u_int32_t   daddr[4];                     /*Destination IP address*/
    u_int16_t   sport;                        /*Source Port*/
    u_int16_t   dport;                        /*Destination Port*/
    u_int32_t   saddr_reply[4];
    u_int32_t   daddr_reply[4];
    u_int16_t   sport_reply;
    u_int16_t   dport_reply;
    u_int16_t   protocol;                     /*TCP, UDP ...*/
    u_int16_t   flags;
    u_int32_t   fwmark;
    u_int32_t   route_id;
    u_int32_t   route_id_reply;
    u_int8_t    sa_dir;
    u_int8_t    sa_nr;
    u_int16_t   sa_handle[4];
    u_int8_t     sa_reply_dir;
    u_int8_t    sa_reply_nr;
    u_int16_t   sa_reply_handle[4];
    u_int32_t   tunnel_route_id;
    u_int32_t   tunnel_route_id_reply;
} __attribute__((__packed__)) fpp_ct6_ex_cmd_t;

/*-------------------------------- IP ----------------------------------------*/ 
#define FPP_CMD_IP_ROUTE                                0x0313
#define FPP_CMD_IPV4_RESET                              0x0316
#define FPP_CMD_IP_ROUTE_CHANGE                         0x0318

#define FPP_CMD_IPV6_RESET                              0x0416

/*Structure representing the command sent to add or remove a Route*/
typedef struct fpp_rt_cmd {
    u_int16_t   action;                     /*Action to perform*/
    u_int16_t   mtu;
    u_int8_t    dst_mac[6];
    u_int16_t   pad;
    char        output_device[IFNAMSIZ];    /* Define on which interface the packets are routing to*/
    char        input_device[IFNAMSIZ];
    char        underlying_input_device[IFNAMSIZ];
    u_int32_t   id;
    u_int32_t   flags;
    u_int32_t   dst_addr[4];
} __attribute__((__packed__)) fpp_rt_cmd_t;

#define FPP_IP_ROUTE_6o4                                (1<<0)
#define FPP_IP_ROUTE_4o6                                (1<<1)

/* Structure representing the command sent to enable/disable Ipsec pre-fragmentation */
typedef struct fpp_ipsec_cmd {
    u_int16_t   pre_frag_en;        
    u_int16_t   rsvd;
} __attribute__((__packed__)) fpp_ipsec_cmd_t;

/* ------------------------------- RTP ---------------------------------------*/
#define FPP_ERR_RTP_STATS_MAX_ENTRIES			1230
#define FPP_ERR_RTP_STATS_STREAMID_ALREADY_USED	1231
#define FPP_ERR_RTP_STATS_STREAMID_UNKNOWN		1232
#define FPP_ERR_RTP_STATS_DUPLICATED			1233
#define FPP_ERR_RTP_STATS_WRONG_DTMF_PT			1234
#define FPP_ERR_RTP_STATS_WRONG_TYPE			1235

#define FPP_CMD_RTP_OPEN                                0x0801
#define FPP_CMD_RTP_UPDATE                              0x0802
#define FPP_CMD_RTP_TAKEOVER                            0x0803
#define FPP_CMD_RTP_CONTROL                             0x0804
#define FPP_CMD_RTP_SPECTX_PLD                          0x0805
#define FPP_CMD_RTP_SPECTX_CTRL                         0x0806
#define FPP_CMD_RTCP_QUERY                              0x0807
#define FPP_CMD_RTP_CLOSE                               0x0808

#define FPP_RTP_TAKEOVER_MODE_TSINCR_FREQ               1
#if defined(LS1043)
#define FPP_RTP_TAKEOVER_MODE_AUTO_SSRC                      2
#else
#define FPP_RTP_TAKEOVER_MODE_SSRC                      2
#endif // LS1043

#define TIMESTAMP_TAKEOVER      0x01
#define SEQ_NUM_TAKEOVER        0x02
#define SSRC_TAKEOVER                   0x04
#define MARKER_BIT_TAKEOVER     0x08
#define SSRC_1_TAKEOVER                 0x10

#define FPP_MAX_SPTX_STRING_SIZE                        160

typedef struct fpp_rtp_open_cmd {
    u_int16_t   call_id;
    u_int16_t   socket_a;
    u_int16_t   socket_b;
    u_int16_t   rsvd;
} __attribute__((__packed__)) fpp_rtp_open_cmd_t;

typedef struct fpp_rtp_close_cmd {
    u_int16_t   call_id;
    u_int16_t   rsvd;
} __attribute__((__packed__)) fpp_rtp_close_cmd_t;

typedef struct fpp_rtp_takeover_cmd {
    u_int16_t   call_id;
    u_int16_t   socket;
    u_int16_t   mode;
    u_int16_t   seq_number_base;
    u_int32_t   ssrc;
    u_int32_t   ts_base;
    u_int32_t   ts_incr;
#if defined(LS1043)
    u_int32_t   ssrc_1;
    u_int8_t   	param_flags;
    u_int8_t   	marker_bit_conf_mode;
    u_int16_t   rsvd;
#endif // LS1043
} __attribute__((__packed__)) fpp_rtp_takeover_cmd_t;

typedef struct fpp_rtp_ctrl_cmd {
    u_int16_t   call_id;
    u_int16_t   control_dir;
#if defined(LS1043)
	u_int16_t	vlan_p_bit_conf;
	u_int16_t	rsvd;
#endif //(LS1043)
} __attribute__((__packed__)) fpp_rtp_ctrl_cmd_t;

#define FPP_RTP_SPEC_TX_START                           0
#define FPP_RTP_SPEC_TX_RESPONSE                        1
#define FPP_RTP_SPEC_TX_STOP                            2

typedef struct fpp_rtp_spec_tx_ctrl_cmd {
    u_int16_t   call_id;
    u_int16_t   type;
} __attribute__((__packed__)) fpp_rtp_spec_tx_ctrl_cmd_t;

typedef struct fpp_rtp_spec_tx_payload_cmd {
    u_int16_t   call_id;
    u_int16_t   payload_id;
    u_int16_t   payload_length;
    u_int16_t   payload[80];
} __attribute__((__packed__)) fpp_rtp_spec_tx_payload_cmd_t;

typedef struct fpp_rtcp_query_cmd {
    u_int16_t   socket_id;
    u_int16_t   flags;
} __attribute__((__packed__)) fpp_rtcp_query_cmd_t;

typedef struct fpp_rtcp_query_res {
    u_int32_t   prev_reception_period;
    u_int32_t   last_reception_period;
    u_int32_t   num_tx_pkts;
    u_int32_t   num_rx_pkts;
    u_int32_t   last_rx_seq;
    u_int32_t   last_rx_timestamp;
    u_int8_t    rtp_header[12];
    u_int32_t   num_rx_dup;
    u_int32_t   num_rx_since_rtcp;
    u_int32_t   num_tx_bytes;
    u_int32_t   min_jitter;
    u_int32_t   max_jitter;
    u_int32_t   average_jitter;
    u_int32_t   num_rx_lost_pkts;
    u_int32_t   min_reception_period;
    u_int32_t   max_reception_period;
    u_int32_t   average_reception_period;
    u_int32_t   num_malformed_pkts;
    u_int32_t   num_expected_pkts;
    u_int32_t   num_late_pkts;
    u_int16_t   sport;
    u_int16_t   dport;
    u_int32_t   num_cumulative_rx_lost_pkts;
    u_int32_t   ssrc_overwrite_value;
} __attribute__((__packed__)) fpp_rtcp_query_res_t;

#define MAX_SOCKET_IN_MSG 10

typedef struct fpp_socketstats_status_cmd {
        u_int16_t rsvd1; /* Reserved for future enchancements. Now by default only query is allowed */
        u_int16_t start_sock_id;
        u_int16_t end_sock_id;
        u_int16_t rsvd2;
} __attribute__((__packed__)) fpp_socketstats_status_cmd_t;

typedef struct fpp_socketstats {
        u_int16_t sock_id;
        u_int16_t rsvd1;
        u_int32_t total_packets_received;
        u_int32_t total_packets_transmitted;
}__attribute__((__packed__)) fpp_socketstats_t;

typedef struct fpp_socketstats_entry_response {
        u_int16_t ackstatus;
        u_int16_t eof;
        u_int16_t socket_no; /* Number of sockets for which stats are given in this response message */
        u_int16_t rsvd1;
        fpp_socketstats_t socket_stats[MAX_SOCKET_IN_MSG];
} __attribute__((__packed__)) fpp_socketstats_entry_response_t;



/*-------------------------------- RTP QoS Measurement -----------------------*/
#define FPP_CMD_RTP_STATS_ENABLE                        0x0810
#define FPP_CMD_RTP_STATS_DISABLE                       0x0811
#define FPP_CMD_RTP_STATS_QUERY                         0x0812
#define FPP_CMD_RTP_STATS_DTMF_PT                       0x0813
#define FPP_CMD_SOCKETSTATS_STATUS              0x0814
#define FPP_CMD_SOCKETSTATS_ENTRY               0x0815

#define FPP_RTPSTATS_TYPE_IP4                           0
#define FPP_RTPSTATS_TYPE_IP6                           1      
#define FPP_RTPSTATS_TYPE_MC4                           2
#define FPP_RTPSTATS_TYPE_MC6                           3
#define FPP_RTPSTATS_TYPE_RLY                           4
#define FPP_RTPSTATS_TYPE_RLY6                          5

typedef struct fpp_rtp_stat_enable_cmd {
    u_int16_t   stream_id;
    u_int16_t   stream_type;
    u_int32_t   saddr[4];
    u_int32_t   daddr[4];
    u_int16_t   sport;
    u_int16_t   dport;
    u_int16_t   proto;
    u_int16_t   mode;
} __attribute__((__packed__)) fpp_rtp_stat_enable_cmd_t;

typedef struct fpp_rtp_stat_disable_cmd {
    u_int16_t   stream_id;
} __attribute__((__packed__)) fpp_rtp_stat_disable_cmd_t;

typedef struct  fpp_rtp_stat_dtmf_pt_cmd {
    u_int16_t   pt; /* 2 payload types coded on 8bits */
} __attribute__((__packed__)) fpp_rtp_stat_dtmf_pt_cmd_t;

/*-------------------------------- Voice Buffer ------------------------------*/
#define FPP_CMD_VOICE_BUFFER_LOAD                       0x0820 
#define FPP_CMD_VOICE_BUFFER_UNLOAD                     0x0821
#define FPP_CMD_VOICE_BUFFER_START                      0x0822
#define FPP_CMD_VOICE_BUFFER_STOP                       0x0823
#define FPP_CMD_VOICE_BUFFER_RESET                      0x0824

#define FPP_VOICE_BUFFER_SCATTER_MAX                    48

typedef struct fpp_voice_buffer_load_cmd {
    u_int16_t   buffer_id;
    u_int16_t   payload_type;
    u_int16_t   frame_size;
    u_int16_t   entries;
    u_int32_t   data_len;
    u_int8_t    page_order[FPP_VOICE_BUFFER_SCATTER_MAX];
    u_int32_t   addr[FPP_VOICE_BUFFER_SCATTER_MAX];
} __attribute__((__packed__)) fpp_voice_buffer_load_cmd_t;

typedef struct fpp_voice_buffer_unload_cmd {
    u_int16_t   buffer_id;
} __attribute__((__packed__)) fpp_voice_buffer_unload_cmd_t;

typedef struct fpp_voice_buffer_start_cmd {
    u_int16_t   socket_id;
    u_int16_t   buffer_id;
    u_int16_t   seq_number_base;
    u_int16_t   padding;
    u_int32_t   ssrc;
    u_int32_t   timestamp_base;
} __attribute__((__packed__)) fpp_voice_buffer_start_cmd_t;

typedef struct fpp_voice_buffer_stop_cmd {
    u_int16_t   socket_id;
} __attribute__((__packed__)) fpp_voice_buffer_stop_cmd_t;
/*-------------------------------- Exceptions --------------------------------*/
#define FPP_CMD_EXPT_QUEUE_DSCP                         0x0C01
#define FPP_CMD_EXPT_QUEUE_CONTROL                      0x0C02
#define FPP_CMD_EXPT_QUEUE_RESET                        0x0C03

#define FPP_EXPT_Q0                                     0
#define FPP_EXPT_Q1                                     1
#define FPP_EXPT_Q2                                     2
#define FPP_EXPT_Q3                                     3
#define FPP_EXPT_MAX_QUEUE                              FPP_EXPT_Q3

#define FPP_EXPT_MAX_DSCP                               63

typedef struct fpp_expt_queue_dscp_cmd {
    u_int16_t   queue;
    u_int16_t   num_dscp;
    u_int8_t    dscp[FPP_EXPT_MAX_DSCP];
    u_int8_t    pad;
} __attribute__((__packed__)) fpp_expt_queue_dscp_cmd_t;

typedef struct fpp_expt_queue_control_cmd {
    u_int16_t   queue;
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_expt_queue_control_cmd_t;

/*-------------------------------- QM ----------------------------------------*/
// 0x0200 -> 0x02FF : QM module
#define FPP_CMD_QM_QOSENABLE                            0x0201
#define FPP_CMD_QM_QOSALG                               0x0202
#define FPP_CMD_QM_NHIGH                                0x0203
#define FPP_CMD_QM_MAX_TXDEPTH                          0x0204
#define FPP_CMD_QM_MAX_QDEPTH                           0x0205
#define FPP_CMD_QM_MAX_WEIGHT                           0x0206
#define FPP_CMD_QM_RATE_LIMIT                           0x0207
#define FPP_CMD_QM_EXPT_RATE                            0x020c
#define FPP_CMD_QM_QUERY                                0x020d
#define FPP_CMD_QM_QUERY_EXPT_RATE                      0x020e
                
#define FPP_CMD_QM_RESET                                0x0210 
#define FPP_CMD_QM_SHAPER_CFG                           0x0211 
#define FPP_CMD_QM_SCHED_CFG                            0x0212 
#define FPP_CMD_QM_DSCP_MAP                             0x0213 
#define FPP_CMD_QM_QUEUE_QOSENABLE                      0x0214

#define FPP_CMD_QM_QUERY_PORTINFO                       0x0220
#define FPP_CMD_QM_QUERY_QUEUE                          0x0221    
#define FPP_CMD_QM_QUERY_SHAPER                         0x0222
#define FPP_CMD_QM_QUERY_SCHED                          0x0223

#define FPP_MAX_DSCP                                    63
#define FPP_NUM_DSCP                                    64

#if defined(COMCERTO_2000) ||  defined(LS1043)
#define FPP_NUM_QUEUES                                  16
#define FPP_PORT_SHAPER_NUM                             0xffff
#else
#define FPP_NUM_QUEUES                                  32
#endif

#ifndef LS1043
#define FPP_NUM_SHAPERS                                 8
#define FPP_NUM_SCHEDULERS                              8
#else
#define FPP_NUM_SHAPERS                                 1
#define FPP_NUM_SCHEDULERS                              1
#endif

#define FPP_EXPT_TYPE_ETH                               0x0
#define FPP_EXPT_TYPE_WIFI                              0x1
#define FPP_EXPT_TYPE_ARP                               0x2
#define FPP_EXPT_TYPE_PCAP                              0x3

typedef struct fpp_qm_qos_enable_cmd {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   enable;
    } __attribute__((__packed__)) fpp_qm_qos_enable_cmd_t;              

    typedef struct fpp_qm_queue_qos_enable_cmd {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   enable_flag;
    u_int32_t   queue_qosenable_mask; // Bit mask of queues on which Qos is enabled
} __attribute__((__packed__)) fpp_qm_queue_qos_enable_cmd_t;

typedef struct fpp_qm_qos_alg_cmd {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   scheduler;
} __attribute__((__packed__)) fpp_qm_qos_alg_cmd_t;
            
typedef struct fpp_qm_nhigh_cmd {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   number_high_queues;
} __attribute__((__packed__)) fpp_qm_nhigh_cmd_t;

typedef struct fpp_qm_max_txdepth_cmd_t {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   max_bytes;
} __attribute__((__packed__)) fpp_qm_max_txdepth_cmd_t;

typedef struct fpp_qm_max_qdepth_cmd {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t    qtxdepth[FPP_NUM_QUEUES];
} __attribute__((__packed__)) fpp_qm_max_qdepth_cmd_t;

typedef struct fpp_qm_max_weight_cmd {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   qxweight[FPP_NUM_QUEUES];
} __attribute__((__packed__)) fpp_qm_max_weight_cmd_t;

typedef struct fpp_qm_rate_limit_cmd {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   enable;
    u_int32_t   queues;
    u_int32_t   rate;
    u_int32_t   bucket_size;
} __attribute__((__packed__)) fpp_qm_rate_limit_cmd_t;

typedef struct fpp_qm_expt_rate_cmd {
    u_int16_t   if_type;
    u_int16_t   pkts_per_msec;
} __attribute__((__packed__)) fpp_qm_expt_rate_cmd_t;

typedef struct fpp_qm_query_rl
{
    u_int16_t   action;
    u_int16_t   mask;
    u_int32_t   aggregate_bandwidth;
    u_int32_t   bucketsize;
} __attribute__((__packed__)) fpp_qm_query_rl_t;

#ifndef COMCERTO_2000
typedef struct fpp_qm_query_cmd
{
    u_int16_t   action;
    u_int16_t   port;
    u_int32_t   queue_qosenable_mask;                       // bit mask of queues on which Qos is enabled
    u_int32_t   max_txdepth;

    u_int32_t   shaper_qmask[FPP_NUM_SHAPERS];              // mask of queues assigned to this shaper
    u_int32_t   tokens_per_clock_period[FPP_NUM_SHAPERS];   // bits worth of tokens available on every 1 msec clock period
    u_int32_t   bucket_size[FPP_NUM_SHAPERS];               // max bucket size in bytes 

    u_int32_t   sched_qmask[FPP_NUM_SCHEDULERS];
    u_int8_t    sched_alg[FPP_NUM_SCHEDULERS];              // current scheduling algorithm

    u_int16_t   max_qdepth[FPP_NUM_QUEUES];
} __attribute__((__packed__)) fpp_qm_query_cmd_t;
#endif

#if defined(COMCERTO_2000) || defined(LS1043)
typedef struct fpp_qm_query_portinfo_cmd
{
    u_int16_t   status;
#ifndef LS1043
    u_int16_t   port;
#else
    char        interface[IFNAMSIZ];
#endif
    u_int32_t   queue_qosenable_mask;       // bit mask of queues on which Qos is enabled
    u_int16_t   max_txdepth;                // ignored on C2000
    u_int8_t    ifg;
    u_int8_t    unused;
} __attribute__((__packed__)) fpp_qm_query_portinfo_cmd_t;

typedef struct fpp_qm_query_queue_cmd
{
    u_int16_t   status;
#ifndef LS1043
    u_int16_t   port;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   queue_num;
    u_int16_t   qweight;
    u_int16_t   max_qdepth;
    u_int16_t   unused;
} __attribute__((__packed__)) fpp_qm_query_queue_cmd_t;

typedef struct fpp_qm_query_shaper_cmd
{
    u_int16_t   status;
#ifndef LS1043
    u_int16_t   port;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   shaper_num;
    u_int8_t    enabled;
    u_int8_t    unused;
    u_int32_t   qmask;
    u_int32_t   rate;
    u_int32_t   bucket_size;
} __attribute__((__packed__)) fpp_qm_query_shaper_cmd_t;

typedef struct fpp_qm_query_sched_cmd
{
    u_int16_t   status;
#ifndef LS1043
    u_int16_t   port;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   sched_num;
    u_int8_t    alg;
    u_int8_t    unused;
    u_int32_t   qmask;
} __attribute__((__packed__)) fpp_qm_query_sched_cmd_t;
#endif

typedef struct fpp_qm_reset_cmd {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_qm_reset_cmd_t;

typedef struct fpp_qm_shaper_cfg {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   shaper;
    u_int16_t   enable;
    u_int8_t    ifg;
    u_int8_t    ifg_change_flag;
    u_int32_t   rate;
    u_int32_t   bucket_size;
    u_int32_t   queues;
} __attribute__((__packed__)) fpp_qm_shaper_cfg_t;

typedef struct fpp_qm_scheduler_cfg {
#ifndef LS1043
    u_int16_t   interface;
#else
    u_int8_t    interface[IFNAMSIZ];
#endif
    u_int16_t   scheduler;
    u_int8_t    algo;
    u_int8_t    algo_change_flag;
    u_int16_t   pad;
    u_int32_t   queues;
} __attribute__((__packed__)) fpp_qm_scheduler_cfg_t;

typedef struct fpp_qm_dscp_queue_mod {
    u_int16_t   queue;
    u_int16_t   num_dscp;
    u_int8_t    dscp[FPP_NUM_DSCP];
} __attribute__((__packed__)) fpp_qm_dscp_queue_mod_t;

/*-------------------------------- RX module ---------------------------------*/
/*Function codes*/
/* 0x00xx : Rx module */
#define FPP_CMD_RX_CNG_ENABLE                           0x0003
#define FPP_CMD_RX_CNG_DISABLE                          0x0004
#define FPP_CMD_RX_CNG_SHOW                             0x0005

#define FPP_CMD_RX_L2BRIDGE_ENABLE                      0x0008
#define FPP_CMD_RX_L2BRIDGE_ADD                         0x0009
#define FPP_CMD_RX_L2BRIDGE_REMOVE                      0x000a
#define FPP_CMD_RX_L2BRIDGE_QUERY_STATUS                0x000b
#define FPP_CMD_RX_L2BRIDGE_QUERY_ENTRY                 0x000c
#define FPP_CMD_RX_L2FLOW_ENTRY                         0x000d
#define FPP_CMD_RX_L2BRIDGE_MODE                        0x000e
#define FPP_CMD_RX_L2BRIDGE_FLOW_TIMEOUT                0x000f
#define FPP_CMD_RX_L2BRIDGE_FLOW_RESET                  0x0010

#define FPP_BRIDGE_QMOD_NONE                            0
#define FPP_BRIDGE_QMOD_DSCP                            1

#define FPP_L2_BRIDGE_MODE_MANUAL                       0
#define FPP_L2_BRIDGE_MODE_AUTO                         1

typedef struct fpp_rx_icc_enable_cmd {
    u_int16_t   interface;
    u_int16_t   acc_value;
    u_int16_t   on_thr;
    u_int16_t   off_thr;
    u_int32_t   flag;
    u_int32_t   val1;
    u_int32_t   val2;
} __attribute__((__packed__)) fpp_rx_icc_enable_cmd_t;

typedef struct fpp_rx_icc_disable_cmd {
    u_int16_t   interface;
} __attribute__((__packed__)) fpp_rx_icc_disable_cmd_t;

typedef struct fpp_rx_icc_show_return_cmd {
    u_int16_t   padding_in_rc_out;
    u_int16_t   state;
    u_int16_t   acc_value;
    u_int16_t   on_thr;
    u_int16_t   off_thr;
} __attribute__((__packed__)) fpp_rx_icc_show_return_cmd_t;

/* L2 Bridging Enable command */
typedef struct fpp_l2_bridge_enable_cmd {
    u_int16_t   interface;
    u_int16_t   enable_flag;
    char        input_name[IFNAMSIZ];
} __attribute__((__packed__)) fpp_l2_bridge_enable_cmd_t;

/* L2 Bridging Add Entry command */
typedef struct fpp_l2_bridge_add_entry_cmd {
    u_int16_t   input_interface;
    u_int16_t   input_svlan;
    u_int16_t   input_cvlan;
    u_int8_t    destaddr[6];
    u_int8_t    srcaddr[6];
    u_int16_t   ethertype;
    u_int16_t   output_interface;
    u_int16_t   output_svlan;
    u_int16_t   output_cvlan;
    u_int16_t   pkt_priority;
    u_int16_t   svlan_priority;
    u_int16_t   cvlan_priority;
    char        input_name[IFNAMSIZ];
    char        output_name[IFNAMSIZ];
    u_int16_t   queue_modifier;
    u_int16_t   session_id;
} __attribute__((__packed__)) fpp_l2_bridge_add_entry_cmd_t;

/* L2 Bridging Remove Entry command */
typedef struct fpp_l2_bridge_remove_entry_cmd {
    u_int16_t   input_interface;
    u_int16_t   input_svlan;
    u_int16_t   input_cvlan;
    u_int8_t    destaddr[6];
    u_int8_t    srcaddr[6];
    u_int16_t   ethertype;
    u_int16_t   session_id;
    u_int16_t   reserved;
    char        input_name[IFNAMSIZ];
} __attribute__((__packed__)) fpp_l2_bridge_remove_entry_cmd_t;

/* L2 Bridging Query Status response */
typedef struct fpp_l2_bridge_query_status_response {
    u_int16_t   ackstatus;
    u_int16_t   status;
    u_int8_t    ifname[IFNAMSIZ];
    u_int32_t   eof;
} __attribute__((__packed__)) fpp_l2_bridge_query_status_response_t;

/* L2 Bridging Query Entry response */
typedef struct fpp_l2_bridge_query_entry_response {
    u_int16_t   ackstatus;
    u_int16_t   eof;
    u_int16_t   input_interface;
    u_int16_t   input_svlan;
    u_int16_t   input_cvlan;
    u_int8_t    destaddr[6];
    u_int8_t    srcaddr[6];
    u_int16_t   ethertype;
    u_int16_t   output_interface;
    u_int16_t   output_svlan;
    u_int16_t   output_cvlan;
    u_int16_t   pkt_priority;
    u_int16_t   svlan_priority;
    u_int16_t   cvlan_priority;
    char        input_name[IFNAMSIZ];
    char        output_name[IFNAMSIZ];
    u_int16_t   queue_modifier;
    u_int16_t   session_id;
} __attribute__((__packed__)) fpp_l2_bridge_query_entry_response_t;

/* L2 Bridging  Flow entry command */
typedef struct fpp_l2_bridge_flow_entry_cmd {
    u_int16_t   action;                /*Action to perform*/
    u_int16_t   ethertype;            /* If VLAN Tag !=0, ethertype of next header */
    u_int8_t    destaddr[6];            /* Dst MAC addr */
    u_int8_t    srcaddr[6];            /* Src MAC addr */
    u_int16_t   svlan_tag;             /* S TCI */
    u_int16_t   cvlan_tag;             /* C TCI */
    u_int16_t   session_id;            /* Meaningful only if ethertype PPPoE */
    u_int16_t   pad1;            
    char        input_name[IFNAMSIZ];        /* Input itf name */
    char        output_name[IFNAMSIZ];    /* Output itf name */
    /* L3-4 optional information*/
    u_int32_t   saddr[4];
    u_int32_t   daddr[4];
    u_int16_t   sport;
    u_int16_t   dport;
    u_int8_t    proto;
    u_int8_t    pad;
    u_int16_t   mark;                /* QoS Mark*/
    u_int32_t   timeout;            /* Entry timeout only for QUERY */
} __attribute__((__packed__)) fpp_l2_bridge_flow_entry_cmd_t;

/* L2 Bridging Control command */
typedef struct fpp_l2_bridge_control_cmd {
    u_int16_t   mode_timeout;        /* Either set bridge mode or set timeout for flow entries */
} __attribute__((__packed__)) fpp_l2_bridge_control_cmd_t;

/*-------------------------------- Stat --------------------------------------*/
/*Function codes*/
/* 0x00xx : Stat module */
#define FPP_CMD_STAT_ENABLE                             0x0E01 
#define FPP_CMD_STAT_QUEUE                              0x0E02  
#define FPP_CMD_STAT_INTERFACE_PKT                      0x0E03
#define FPP_CMD_STAT_CONNECTION                         0x0E04
#define FPP_CMD_STAT_PPPOE_STATUS                       0x0E05
#define FPP_CMD_STAT_PPPOE_ENTRY                        0x0E06
#define FPP_CMD_STAT_BRIDGE_STATUS                      0x0E07
#define FPP_CMD_STAT_BRIDGE_ENTRY                       0x0E08
#define FPP_CMD_STAT_IPSEC_STATUS                       0x0E09
#define FPP_CMD_STAT_IPSEC_ENTRY                        0x0E0A
#define FPP_CMD_STAT_VLAN_STATUS                        0x0E0B
#define FPP_CMD_STAT_VLAN_ENTRY                         0x0E0C
#define FPP_CMD_STAT_TUNNEL_STATUS                      0x0E0D
#define FPP_CMD_STAT_TUNNEL_ENTRY                       0x0E0E
#define FPP_CMD_STAT_FLOW                               0x0E0F
#define FPP_CMD_IPR_V4_STATS                            0x0E10
#define FPP_CMD_IPR_V6_STATS                            0x0E11

#define FPP_CMM_STAT_RESET                              0x0001
#define FPP_CMM_STAT_QUERY                              0x0002
#define FPP_CMM_STAT_QUERY_RESET                        0x0003

#define FPP_CMM_STAT_ENABLE                             0x0001
#define FPP_CMM_STAT_DISABLE                            0x0000

/* Definitions of Bit Masks for the features */
#define FPP_STAT_QUEUE_BITMASK                          0x00000001
#define FPP_STAT_INTERFACE_BITMASK                      0x00000002
#define FPP_STAT_PPPOE_BITMASK                          0x00000008
#define FPP_STAT_BRIDGE_BITMASK                         0x00000010
#define FPP_STAT_IPSEC_BITMASK                          0x00000020
#define FPP_STAT_VLAN_BITMASK                           0x00000040
#define FPP_STAT_TUNNEL_BITMASK                         0x00000080
#define FPP_STAT_FLOW_BITMASK                           0x00000100

#define FPP_STAT_UNKNOWN_CMD                            0
#define FPP_STAT_ENABLE_CMD                             1 
#define FPP_STAT_QUEUE_CMD                              2
#define FPP_STAT_INTERFACE_PKT_CMD                      3
#define FPP_STAT_CONNECTION_CMD                         4
#define FPP_STAT_PPPOE_CMD                              5
#define FPP_STAT_BRIDGE_CMD                             6
#define FPP_STAT_IPSEC_CMD                              7
#define FPP_STAT_VLAN_CMD                               8
#define FPP_STAT_TUNNEL_CMD                             9
#define FPP_STAT_FLOW_CMD                               10

typedef struct fpp_stat_enable_cmd {
    u_int16_t   action; /* 1 - Enable, 0 - Disable */
    u_int16_t   pad;
    u_int32_t   bitmask; /* Specifies the feature to be enabled or disabled */
} __attribute__((__packed__)) fpp_stat_enable_cmd_t;

typedef struct fpp_stat_queue_cmd {
    u_int16_t   action; /* Reset, Query, Query & Reset */
    u_int16_t   interface;
    u_int16_t   queue;
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_stat_queue_cmd_t;

typedef struct fpp_stat_interface_cmd {
    u_int16_t   action; /* Reset, Query, Query & Reset */
    u_int16_t   interface;
} __attribute__((__packed__)) fpp_stat_interface_cmd_t;

typedef struct fpp_stat_connection_cmd {
    u_int16_t   action; /* Reset, Query, Query & Reset */
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_stat_connection_cmd_t;

typedef struct fpp_stat_pppoe_status_cmd {
    u_int16_t   action; /* Reset, Query, Query & Reset */
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_stat_pppoe_status_cmd_t;

typedef struct fpp_stat_bridge_status_cmd {
    u_int16_t   action; /* Reset, Query, Query & Reset */
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_stat_bridge_status_cmd_t;

typedef struct fpp_stat_ipsec_status_cmd {
    u_int16_t    action; /* Reset, Query, Query & Reset */
    u_int16_t    pad;
} __attribute__((__packed__)) fpp_stat_ipsec_status_cmd_t;

typedef struct fpp_stat_vlan_status_cmd {
    u_int16_t   action; /* Reset, Query, Query & Reset */
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_stat_vlan_status_cmd_t;

typedef struct fpp_stat_tunnel_status_cmd {
    u_int16_t   action; /* Reset, Query, Query & Reset */
    u_int16_t   pad;
    char        if_name[IFNAMSIZ];
} __attribute__((__packed__)) fpp_stat_tunnel_status_cmd_t;

typedef struct fpp_stat_flow_status_cmd {
    u_int8_t    action;
    u_int8_t    pad;
    u_int8_t    ip_family;
    u_int8_t    Protocol;
    u_int16_t   Sport;        /*Source Port*/
    u_int16_t   Dport;        /*Destination Port*/
    union {
        struct {
            u_int32_t   Saddr;          /*Source IPv4 address*/
            u_int32_t   Daddr;          /*Destination IPv4 address*/
        };
        struct {
            u_int32_t   Saddr_v6[4];    /*Source IPv6 address*/
            u_int32_t   Daddr_v6[4];    /*Destination IPv6 address*/
        };
    };
} __attribute__((__packed__)) fpp_stat_flow_status_cmd_t;

typedef struct fpp_stat_queue_response {
    u_int16_t   ackstatus; 
    u_int16_t   rsvd1;
    u_int32_t   peak_queue_occ; 
    u_int32_t   emitted_pkts; 
    u_int32_t   dropped_pkts; 
} __attribute__((__packed__)) fpp_stat_queue_response_t;

typedef struct fpp_stat_interface_pkt_response {
    u_int16_t   ackstatus;
    u_int16_t   rsvd1;
    u_int32_t   total_pkts_transmitted;
    u_int32_t   total_pkts_received;
    u_int32_t   total_bytes_transmitted[2]; /* 64 bit counter stored as 2*32 bit counters */ 
    u_int32_t   total_bytes_received[2]; /* 64 bit counter stored as 2*32 bit counters */
} __attribute__((__packed__)) fpp_stat_interface_pkt_response_t;

typedef struct fpp_stat_conn_response {
    u_int16_t   ackstatus;
    u_int16_t   rsvd1;
    u_int32_t   max_active_connections;
    u_int32_t   num_active_connections;
} __attribute__((__packed__)) fpp_stat_conn_response_t;

typedef struct fpp_stat_pppoe_status_response {
    u_int16_t   ackstatus;
} __attribute__((__packed__)) fpp_stat_pppoe_status_response_t;

typedef struct fpp_stat_pppoe_entry_response {
    u_int16_t   ackstatus;
    u_int16_t   eof;
    u_int16_t   sessionid;
    u_int16_t   interface_no; /* WAN_PORT_ID for WAN & LAN_PORT_ID for LAN */
    u_int32_t   total_packets_received;  
    u_int32_t   total_packets_transmitted; 
} __attribute__((__packed__)) fpp_stat_pppoe_entry_response_t;

typedef struct fpp_stat_bridge_status_response {
    u_int16_t    ackstatus;
} __attribute__((__packed__)) fpp_stat_bridge_status_response_t;

typedef struct fpp_stat_bridge_entry_response {
    u_int16_t   ackstatus;
    u_int16_t   eof;
    u_int16_t   input_interface;
    u_int16_t   input_svlan; 
    u_int16_t   input_cvlan; 
    u_int8_t    dst_mac[6];
    u_int8_t    src_mac[6];
    u_int16_t   ether_type;
    u_int16_t   output_interface;
    u_int16_t   output_svlan; 
    u_int16_t   output_cvlan; 
    u_int16_t   session_id;
    u_int32_t   total_packets_transmitted; 
    char        input_name[IFNAMSIZ];
    char        output_name[IFNAMSIZ];
} __attribute__((__packed__)) fpp_stat_bridge_entry_response_t;

typedef struct fpp_stat_ipsec_entry_response {
    u_int16_t   ackstatus;
    u_int16_t   eof;
    u_int16_t   family;
    u_int16_t   proto;
    u_int32_t   spi;
    u_int32_t   dst_ip[4];
    u_int32_t   total_pkts_processed;
    u_int32_t   total_bytes_processed[2];
    u_int16_t   sagd;
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_stat_ipsec_entry_response_t;

typedef struct fpp_stat_vlan_entry_response {
    u_int16_t   ackstatus;
    u_int16_t   eof;
    u_int16_t   vlanID;
    u_int16_t   rsvd;
    u_int32_t   total_packets_received;  
    u_int32_t   total_packets_transmitted; 
    u_int32_t   total_bytes_received[2];  
    u_int32_t   total_bytes_transmitted[2];     
    unsigned char vlanifname[IFNAMSIZ];
    unsigned char phyifname[IFNAMSIZ];
} __attribute__((__packed__)) fpp_stat_vlan_entry_response_t;

typedef struct fpp_stat_tunnel_entry_response {
    u_int16_t   ackstatus;
    u_int16_t   eof;
    u_int32_t   rsvd;
    u_int32_t   total_packets_received;
    u_int32_t   total_packets_transmitted;
    u_int32_t   total_bytes_received[2];
    u_int32_t   total_bytes_transmitted[2];
    unsigned char if_name[IFNAMSIZ];
} __attribute__((__packed__)) fpp_stat_tunnel_entry_response_t;

typedef struct fpp_stat_flow_entry_response {
    u_int16_t   ackstatus;
    u_int8_t    ip_family;
    u_int8_t    Protocol;
    u_int16_t   Sport;        /*Source Port*/
    u_int16_t   Dport;        /*Destination Port*/
    union {
        struct {
            u_int32_t    Saddr;        /*Source IPv4 address*/
            u_int32_t    Daddr;        /*Destination IPv4 address*/
        };
        struct {
            u_int32_t    Saddr_v6[4];        /*Source IPv6 address*/
            u_int32_t    Daddr_v6[4];        /*Destination IPv6 address*/
        };
    };
    u_int64_t   TotalPackets;
    u_int64_t   TotalBytes;
} __attribute__((__packed__)) fpp_stat_flow_entry_response_t;

/*-------------------------------- Altconf -----------------------------------*/
#define FPP_CMD_ALTCONF_SET                             0x1001
#define FPP_CMD_ALTCONF_RESET                           0x1002

/* option IDs */
#define FPP_ALTCONF_OPTION_MCTTL                        0x0001 /* Multicast TTL option */
#define FPP_ALTCONF_OPTION_IPSECRL                      0x0002 /* IPSEC Rate Limiting option */
#define FPP_ALTCONF_OPTION_ALL                          0xFFFF
#define FPP_ALTCONF_OPTION_MAX                          FPP_ALTCONF_OPTION_IPSECRL + 1 /*include the "all" option*/

#define FPP_ALTCONF_MODE_DEFAULT                        0 /* Same default value used for all options */
#define FPP_ALTCONF_OPTION_MAX_PARAMS                   3 /* IPSEC Rate Limiting has 3 parameters. */
                                                          /* To be updated if a new option is add with more 32bits params */
/* ALL options */
#define FPP_ALTCONF_ALL_NUM_PARAMS                      1
#define FPP_ALTCONF_ALL_MODE_DEFAULT                    FPP_ALTCONF_MODE_DEFAULT

/* Multicast TTL Configuration definitions */
#define FPP_ALTCONF_MCTTL_MODE_DEFAULT                  FPP_ALTCONF_MODE_DEFAULT
#define FPP_ALTCONF_MCTTL_MODE_IGNORE                   1
#define FPP_ALTCONF_MCTTL_MODE_MAX                      FPP_ALTCONF_MCTTL_MODE_IGNORE
#define FPP_ALTCONF_MCTTL_NUM_PARAMS                    1 /* Maximum number of u32 allowed for this option */

/* IPSEC Rate Limiting Configuration definitions */
#define FPP_ALTCONF_IPSECRL_OFF                         0
#define FPP_ALTCONF_IPSECRL_ON                          1
#define FPP_ALTCONF_IPSECRL_NUM_PARAMS                  3 /* Maximum number of u32 allowed for this option */

typedef struct fpp_alt_set_cmd {
    u_int16_t   option_id;
    u_int16_t   num_params;
    u_int32_t   params[FPP_ALTCONF_OPTION_MAX_PARAMS];
} __attribute__((__packed__)) fpp_alt_set_cmd_t;

/*-------------------------------- NATPT -------------------------------------*/
#define FPP_CMD_NATPT_OPEN                              0x1101
#define FPP_CMD_NATPT_CLOSE                             0x1102
#define FPP_CMD_NATPT_QUERY                             0x1103

#define FPP_NATPT_CONTROL_6to4                          0x01
#define FPP_NATPT_CONTROL_4to6                          0x02
#define FPP_NATPT_CONTROL_TCPFIN                        0x0100  

typedef struct fpp_natpt_open_cmd {
    u_int16_t   socket_a;
    u_int16_t   socket_b;
    u_int16_t   control;
    u_int16_t   rsvd1;
} __attribute__((__packed__)) fpp_natpt_open_cmd_t;

typedef struct fpp_natpt_close_cmd {
    u_int16_t   socket_a;
    u_int16_t   socket_b;
} __attribute__((__packed__)) fpp_natpt_close_cmd;

typedef struct fpp_natpt_query_cmd {
    u_int16_t   reserved1;
    u_int16_t   socket_a;
    u_int16_t   socket_b;
    u_int16_t   reserved2;
} __attribute__((__packed__)) fpp_natpt_query_cmd_t;

typedef struct fpp_natpt_query_response {
    u_int16_t   retcode;
    u_int16_t   socket_a;
    u_int16_t   socket_b;
    u_int16_t   control;
    u_int64_t   stat_v6_received;
    u_int64_t   stat_v6_transmitted;
    u_int64_t   stat_v6_dropped;
    u_int64_t   stat_v6_sent_to_ACP;
    u_int64_t   stat_v4_received;
    u_int64_t   stat_v4_transmitted;
    u_int64_t   stat_v4_dropped;
    u_int64_t   stat_v4_sent_to_ACP;
} __attribute__((__packed__)) fpp_natpt_query_response_t;

/*-------------------------------- Fast Forwarding ---------------------------*/
#define FPP_CMD_IPV4_FF_CONTROL                         0x0321

/* Structure representing the command sent to enable/disable fast-forward */
typedef struct fpp_ff_ctrl_cmd {
    u_int16_t   enable;
    u_int16_t   reserved;
} __attribute__((__packed__)) fpp_ff_ctrl_cmd_t;

/*-------------------------------- VLAN --------------------------------------*/
#define FPP_CMD_VLAN_ENTRY                              0x0901
#define FPP_CMD_VLAN_RESET                              0x0902

/* VLAN command as understood by FPP */
typedef struct fpp_vlan_cmd {
    u_int16_t   action;
    u_int16_t   vlan_id; // Carries skip count for ACTION_QUERY
    char        vlan_ifname[IFNAMSIZ];
    char        vlan_phy_ifname[IFNAMSIZ];
} __attribute__((__packed__)) fpp_vlan_cmd_t;

/*-------------------------------- MacVlan -----------------------------------*/
#define FPP_CMD_MACVLAN_ENTRY                           0x1401
#define FPP_CMD_MACVLAN_RESET                           0x1402

/* MacVlan command as understood by FPP */
typedef struct fpp_macvlan_cmd {
    u_int16_t       action;
    unsigned char   macaddr[6]; 
    char            macvlan_ifname[IFNAMSIZ];
    char            macvlan_phy_ifname[IFNAMSIZ];
} __attribute__((__packed__)) fpp_macvlan_cmd_t;

/*-------------------------------- Ipsec -------------------------------------*/
/* 0x0axx : IPSec module */
#define FPP_CMD_IPSEC_SA_ADD                            0x0a01
#define FPP_CMD_IPSEC_SA_DELETE                         0x0a02
#define FPP_CMD_IPSEC_SA_FLUSH                          0x0a03
#define FPP_CMD_IPSEC_SA_SET_KEYS                       0x0a04
#define FPP_CMD_IPSEC_SA_SET_TUNNEL                     0x0a05
#define FPP_CMD_IPSEC_SA_SET_NATT                       0x0a06
#define FPP_CMD_IPSEC_SA_SET_STATE                      0x0a07
#define FPP_CMD_IPSEC_SA_SET_LIFETIME                   0x0a08
#define FPP_CMD_IPSEC_SA_NOTIFY                         0x0a09 
#define FPP_CMD_IPSEC_SA_ACTION_QUERY                   0x0a0a 
#define FPP_CMD_IPSEC_SA_ACTION_QUERY_CONT              0x0a0b 
#define FPP_CMD_IPSEC_FLOW_ADD                          0x0a11
#define FPP_CMD_IPSEC_FLOW_REMOVE                       0x0a12
#define FPP_CMD_IPSEC_FLOW_NOTIFY                       0x0a13
#define FPP_CMD_IPSEC_FRAG_CFG                          0x0a14
#define FPP_CMD_IPSEC_SA_TNL_ROUTE                      0x0a15
#define FPP_CMD_IPSEC_SA_ACTION_SHOW                    0x0a16

#define FPP_CMD_NETKEY_SA_ADD                           FPP_CMD_IPSEC_SA_ADD
#define FPP_CMD_NETKEY_SA_DELETE                        FPP_CMD_IPSEC_SA_DELETE
#define FPP_CMD_NETKEY_SA_FLUSH                         FPP_CMD_IPSEC_SA_FLUSH
#define FPP_CMD_NETKEY_SA_SET_KEYS                      FPP_CMD_IPSEC_SA_SET_KEYS
#define FPP_CMD_NETKEY_SA_SET_TUNNEL                    FPP_CMD_IPSEC_SA_SET_TUNNEL
#define FPP_CMD_NETKEY_SA_SET_NATT                      FPP_CMD_IPSEC_SA_SET_NATT
#define FPP_CMD_NETKEY_SA_SET_STATE                     FPP_CMD_IPSEC_SA_SET_STATE
#define FPP_CMD_NETKEY_SA_SET_LIFETIME                  FPP_CMD_IPSEC_SA_SET_LIFETIME
#define FPP_CMD_NETKEY_FLOW_ADD                         FPP_CMD_IPSEC_FLOW_ADD
#define FPP_CMD_NETKEY_FLOW_REMOVE                      FPP_CMD_IPSEC_FLOW_REMOVE
#define FPP_CMD_NETKEY_FLOW_NOTIFY                      FPP_CMD_IPSEC_FLOW_NOTIFY

typedef struct fpp_sa_query_cmd {
    u_int16_t   action;
    u_int16_t   handle; /* handle */
    /* SPI information */
    u_int16_t   mtu;    /* mtu configured */
    u_int16_t   rsvd1;
    u_int32_t   spi;      /* spi */
    u_int8_t    sa_type; /* SA TYPE Prtocol ESP/AH */
    u_int8_t    family; /* Protocol Family */
    u_int8_t    mode; /* Tunnel/Transport mode */
    u_int8_t    replay_window; /* Replay Window */
    u_int32_t   dst_ip[4];
    u_int32_t   src_ip[4];

      /* Key information */
    u_int8_t    key_alg;
    u_int8_t    state; /* SA VALID /EXPIRED / DEAD/ DYING */
    u_int16_t   flags; /* ESP AH enabled /disabled */

    u_int8_t    cipher_key[32];
    u_int8_t    auth_key[20];
    u_int8_t    ext_auth_key[12];


    /* Tunnel Information */
    u_int8_t    tunnel_proto_family;
    u_int8_t    rsvd[3];
    union {
        struct {
            u_int32_t   daddr;
            u_int32_t   saddr;
            u_int8_t    tos;
            u_int8_t    protocol;
            u_int16_t   total_length;
        } ipv4;

        struct {
            u_int32_t   traffic_class_hi:4;
            u_int32_t   version:4;
            u_int32_t   flow_label_high:4;
            u_int32_t   traffic_class:4;
            u_int32_t   flow_label_lo:16;
            u_int32_t   daddr[4];
            u_int32_t   saddr[4];
        } ipv6;
    } tnl;

    u_int64_t   soft_byte_limit;
    u_int64_t   hard_byte_limit;
    u_int64_t   soft_packet_limit;
    u_int64_t   hard_packet_limit;
} __attribute__((__packed__)) fpp_sa_query_cmd_t;

/*-------------------------------- PPPoE -------------------------------------*/
#define FPP_CMD_PPPOE_ENTRY                             0x0601
#define FPP_CMD_PPPOE_GET_IDLE                          0x0603
#define FPP_CMD_PPPOE_RELAY_ENTRY                       0x0610
#define FPP_CMD_PPPOE_RELAY_ADD                         0x0611
#define FPP_CMD_PPPOE_RELAY_REMOVE                      0x0612

/* Structure representing the command sent to add or remove a pppoe session */
typedef struct fpp_pppoe_cmd {
    u_int16_t   action;             /*Action to perform*/
    u_int16_t   sessionid;
    u_int8_t    macaddr[6];
    char        phy_intf[IFNAMSIZ];
    char        log_intf[IFNAMSIZ];
    u_int16_t   mode;
} __attribute__((__packed__)) fpp_pppoe_cmd_t;

typedef struct fpp_pppoe_idle {
    char        ppp_if[IFNAMSIZ];
    u_int32_t   xmit_idle;
    u_int32_t   recv_idle;
} __attribute__((__packed__)) fpp_pppoe_idle_t;

typedef struct fpp_relay_info {
    u_int8_t    peermac1[6];
    u_int8_t    peermac2[6];
    char        ipifname[IFNAMSIZ];
    char        opifname[IFNAMSIZ];
    u_int16_t   sesID;
    u_int16_t   relaysesID;
} __attribute__((__packed__)) fpp_relay_info_t;

/* Structure representing the command sent to add or remove a pppoe session */
typedef struct fpp_pppoe_relay_cmd {
    u_int16_t   action;      /*Action to perform */
    u_int8_t    peermac1[6];
    u_int8_t    peermac2[6];
    u_int8_t    ipif_mac[6];
    u_int8_t    opif_mac[6];
    char        ipifname[IFNAMSIZ];
    char        opifname[IFNAMSIZ];
    u_int16_t   sesID;
    u_int16_t   relaysesID;
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_pppoe_relay_cmd_t;

#ifdef WIFI_ENABLE
/*-------------------------------- WiFi --------------------------------------*/
//0x2000: WiFi module
#define FPP_CMD_WIFI_VAP_ENTRY                          0x2001
#define FPP_CMD_VWD_ENABLE                              0x2002
#define FPP_CMD_VWD_DISABLE                             0x2003
#define FPP_CMD_WIFI_VAP_QUERY                          0x2004
#define FPP_CMD_WIFI_VAP_RESET                          0x2005

typedef struct fpp_wifi_vap_query_response
{
    u_int16_t   vap_id;
    char        ifname[IFNAMSIZ];
    u_int16_t   phy_port_id;
} __attribute__((__packed__)) fpp_wifi_vap_query_response_t;

typedef struct fpp_wifi_cmd
{
#define FPP_VWD_VAP_ADD                                 0
#define FPP_VWD_VAP_REMOVE                              1
#define FPP_VWD_VAP_UPDATE                              2
#define FPP_VWD_VAP_RESET                               3
#define FPP_VWD_VAP_CONFIGURE                           4
    u_int16_t   action;
    u_int16_t   vap_id;
    char        ifname[IFNAMSIZ];
    char        mac_addr[6];
    u_int16_t   wifi_guest_flag;
} __attribute__((__packed__)) fpp_wifi_cmd_t;
#endif /* WIFI_ENABLE */

/*-------------------------------- Tunnel ------------------------------------*/
#define FPP_CMD_TUNNEL_ADD                              0x0B01
#define FPP_CMD_TUNNEL_DEL                              0x0B02
#define FPP_CMD_TUNNEL_UPDATE                           0x0B03
#define FPP_CMD_TUNNEL_SEC                              0x0B04
#define FPP_CMD_TUNNEL_QUERY                            0x0B05
#define FPP_CMD_TUNNEL_QUERY_CONT                       0x0B06
#define FPP_CMD_TUNNEL_4rd_ID_CONV_dport                0x0B07
#define FPP_CMD_TUNNEL_4rd_ID_CONV_psid                 0x0B08

/* CMM / FPP API Command */
typedef struct fpp_tunnel_create_cmd {
    char        name[IFNAMSIZ];
    u_int32_t   local[4];
    u_int32_t   remote[4];
    char        output_device[IFNAMSIZ];
    u_int8_t    mode;
    u_int8_t    secure;
    u_int8_t    encap_limit;
    u_int8_t    hop_limit;
    u_int32_t   flow_info; /* Traffic class and FlowLabel */
    u_int16_t   frag_off;
    u_int16_t   enabled;
    u_int32_t   route_id;
    u_int16_t   mtu;
    u_int16_t   pad;
} __attribute__((__packed__)) fpp_tunnel_create_cmd_t;

typedef struct fpp_tunnel_del_cmd {
    char        name[IFNAMSIZ];
} __attribute__((__packed__)) fpp_tunnel_del_cmd_t;

typedef struct fpp_tunnel_sec_cmd {
    char        name[IFNAMSIZ];
    u_int16_t   sa_nr;
    u_int16_t   sa_reply_nr;
    u_int16_t   sa_handle[4];
    u_int16_t   sa_reply_handle[4];
} __attribute__((__packed__)) fpp_tunnel_sec_cmd_t;

/* CMM / FPP API Command */
typedef struct fpp_tunnel_query_cmd {
    unsigned short  result;
    unsigned short  unused;
    char            name[IFNAMSIZ];
    u_int32_t       local[4];
    u_int32_t       remote[4];
    u_int8_t        mode;
    u_int8_t        secure;
    u_int8_t        encap_limit;
    u_int8_t        hop_limit;
    u_int32_t       flow_info; /* Traffic class and FlowLabel */
    u_int16_t       frag_off;
    u_int16_t       enabled;
    u_int32_t       route_id;
    u_int16_t       mtu;
    u_int16_t       pad;
} __attribute__((__packed__)) fpp_tunnel_query_cmd_t;

#ifdef SAM_LEGACY

typedef struct {
    int         port_set_id;        /**< Port Set ID        */
    int         port_set_id_length; /**< Port Set ID length */
    int         psid_offset;        /**< PSID offset        */
}sam_port_info_t;
typedef sam_port_info_t rt_mw_ipstack_sam_port_t;

typedef struct fpp_tunnel_id_conv_cmd {
    u_int8_t        name[IFNAMSIZ];
    sam_port_info_t sam_port_info;
    u_int32_t       IdConvStatus:1,
                    unused:31;
} __attribute__((__packed__)) fpp_tunnel_id_conv_cmd_t;

#else /* SAM_LEGACY */
typedef struct fpp_tunnel_id_conv_cmd {
    u_int16_t   IdConvStatus;
    u_int16_t   Pad;
} __attribute__((__packed__)) fpp_tunnel_id_conv_cmd_t;
#endif /* SAM_LEGACY */

/*-------------------------------- Timeout -----------------------------------*/
#define FPP_CMD_IPV4_SET_TIMEOUT                        0x0319
#define FPP_CMD_IPV4_GET_TIMEOUT                        0x0320
#define FPP_CMD_IPV4_FRAGTIMEOUT                        0x0333
#define FPP_CMD_IPV4_SAMFRAGTIMEOUT                     0x0334
#define FPP_CMD_IPV6_GET_TIMEOUT                        0x0420
#define FPP_CMD_IPV6_FRAGTIMEOUT                        0x0433

/* Timeout Update command */
typedef struct fpp_timeout_cmd {
    u_int16_t   protocol;
    u_int16_t   sam_4o6_timeout;
    u_int32_t   timeout_value1;
    u_int32_t   timeout_value2;
} __attribute__((__packed__)) fpp_timeout_cmd_t;

typedef struct fpp_frag_timeout_cmd {
    u_int16_t   timeout;
    u_int16_t   mode;
} __attribute__((__packed__)) fpp_frag_timeout_cmd_t;

/*-------------------------------- PKTCAP ------------------------------------*/
#define FPP_CMD_PKTCAP_IFSTATUS                         0x0d02
#define FPP_CMD_PKTCAP_FLF                              0x0d03
#define FPP_CMD_PKTCAP_SLICE                            0x0d04
#define FPP_CMD_PKTCAP_QUERY                            0x0d05

#define FPP_PKTCAP_STATUS                               0x1
#define FPP_PKTCAP_SLICE                                0x2
#define MAX_FLF_INSTRUCTIONS                            30

typedef struct fpp_pktcap_status_cmd{
    u_int16_t   action;
    u_int8_t    ifindex;
    u_int8_t    status;
}__attribute__((__packed__)) fpp_pktcap_status_cmd_t;

typedef struct fpp_pktcap_slice_cmd{
    u_int16_t   action;
    u_int8_t    ifindex;
    u_int8_t    rsvd;
    u_int16_t   slice;
}__attribute__((__packed__)) fpp_pktcap_slice_cmd_t;

typedef struct fpp_pktcap_query_cmd{
    u_int16_t   slice;
    u_int16_t   status;
}__attribute__((__packed__)) fpp_pktcap_query_cmd_t;

typedef struct fpp_pktcap_flf_cmd { /* First level filter */
    u_int16_t flen; /* filter length */
    unsigned char   ifindex;
    unsigned char   mfg; /*  The most significant bit tells fpp if more fragments are expected.
                            The least significant 3 bits give the sequence no of the fragment.  */
    struct bpf_insn filter[MAX_FLF_INSTRUCTIONS];
}__attribute__((__packed__)) fpp_pktcap_flf_cmd_t;

/*-------------------------------- PKTCAP ------------------------------------*/
/* Port Update command - begin */
#define FPP_CMD_PORT_UPDATE                             0x0505
typedef struct fpp_port_update_cmd {
    u_int16_t   port_id;
    char        ifname[IFNAMSIZ];
}__attribute__((__packed__)) fpp_port_update_cmd_t;

/*-------------------------------- ICC ---------------------------------------*/
#define FPP_CMD_ICC_RESET                               0x1500
#define FPP_CMD_ICC_THRESHOLD                           0x1501
#define FPP_CMD_ICC_ADD_DELETE                          0x1502
#define FPP_CMD_ICC_QUERY                               0x1503     

typedef struct fpp_icc_reset_cmd {
    u_int16_t   reserved1;
    u_int16_t   reserved2;
} __attribute__((__packed__)) fpp_icc_reset_cmd_t;

typedef struct fpp_icc_threshold_cmd {
    u_int16_t   bmu1_threshold;
    u_int16_t   bmu2_threshold;
} __attribute__((__packed__)) fpp_icc_threshold_cmd_t;

typedef struct fpp_icc_add_delete_cmd {
    u_int16_t   action;
    u_int8_t    interface;
    u_int8_t    table_type;
    union {
        struct {
            u_int16_t type;
        } ethertype;
        struct {
            u_int8_t ipproto[256 / 8];
        } protocol;
        struct {
            u_int8_t dscp_value[64 / 8];
        } dscp;
        struct {
            u_int32_t v4_addr;
            u_int8_t v4_masklen;
        } ipaddr;
        struct {
            u_int32_t v6_addr[4];
            u_int8_t v6_masklen;
        } ipv6addr;
        struct {
            u_int16_t sport_from;
            u_int16_t sport_to;
            u_int16_t dport_from;
            u_int16_t dport_to;
        } port;
        struct {
            u_int16_t vlan_from;
            u_int16_t vlan_to;
            u_int16_t prio_from;
            u_int16_t prio_to;
        } vlan;
    };
} __attribute__((__packed__)) fpp_icc_add_delete_cmd_t;

typedef struct fpp_icc_query_cmd {
    u_int16_t   action;
    u_int8_t    interface;
    u_int8_t    reserved;
} __attribute__((__packed__)) fpp_icc_query_cmd_t;

typedef struct fpp_icc_query_reply {
    u_int16_t   rtncode;
    u_int16_t    query_result;
    u_int8_t    interface;
    u_int8_t    table_type;
    union {
        struct {
            u_int16_t type;
        } ethertype;
        struct {
            u_int8_t ipproto[256 / 8];
        } protocol;
        struct {
            u_int8_t dscp_value[64 / 8];
        } dscp;
        struct {
            u_int32_t v4_addr;
            u_int8_t v4_masklen;
        } ipaddr;
        struct {
            u_int32_t v6_addr[4];
            u_int8_t v6_masklen;
        } ipv6addr;
        struct {
            u_int16_t sport_from;
            u_int16_t sport_to;
            u_int16_t dport_from;
            u_int16_t dport_to;
        } port;
        struct {
            u_int16_t vlan_from;
            u_int16_t vlan_to;
            u_int16_t prio_from;
            u_int16_t prio_to;
        } vlan;
    };
} __attribute__((__packed__)) fpp_icc_query_reply_t;

/*-------------------------------- L2TP --------------------------------------*/
#define FPP_CMD_L2TP_ITF_ADD                            0x1600
#define FPP_CMD_L2TP_ITF_DEL                            0x1601

typedef struct fpp_l2tp_itf_add_cmd {
    char ifname[IFNAMSIZ];
    u_int16_t   sock_id;
    u_int16_t   local_tun_id;
    u_int16_t   peer_tun_id;
    u_int16_t   local_ses_id;
    u_int16_t   peer_ses_id;
    u_int16_t   options;    
}__attribute__((__packed__)) fpp_l2tp_itf_add_cmd_t;

typedef struct fpp_l2tp_itf_del_cmd {
    char        ifname[IFNAMSIZ];
}__attribute__((__packed__)) fpp_l2tp_itf_del_cmd_t;

#endif /* __FPP__ */
