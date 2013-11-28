/**
 * project configuration file
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

// disable TCP support to save ROM and RAM
#define UIP_CONF_TCP    0

/* configure number of neighbors and routes
 * NOTE: this considerably decreases RAM requirements of Contiki */
#undef UIP_CONF_DS6_NBR_NBU
#define UIP_CONF_DS6_NBR_NBU     4
#undef UIP_CONF_DS6_ROUTE_NBU
#define UIP_CONF_DS6_ROUTE_NBU   4

#define SICSLOWPAN_CONF_SPLIT_BUFFER                   1
#define SICSLOWPAN_REPUTATION_SHORTTIME                1      // reputation based on current reassembly window
#define REPUTATION_SHORTTIME_WINDOW                    32     // window in clocks window is from [a-w, a+w]

/* Increase the 6LowPAN reassembly and UIP buffer to maximum packet length */
#undef UIP_CONF_BUFFER_SIZE
#define UIP_CONF_BUFFER_SIZE            1080

#endif /* PROJECT_CONF_H_ */
