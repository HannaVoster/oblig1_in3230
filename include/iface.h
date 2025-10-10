#ifndef IFACE_H
#define IFACE_H

#define ETH_P_MIP 0x88B5 //gitt av oppgaven
extern int iface_indices[5];
extern int iface_count;

int get_iface_mac(const char *ifname, unsigned char *mac);
void find_all_ifaces(void);
int create_raw_socket();

#endif